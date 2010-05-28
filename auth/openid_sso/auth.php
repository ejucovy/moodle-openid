<?php

/**
 * Authentication Plugin: OpenID Single Sign-On (SSO) Authentication
 *
 * This plugin provides OpenID SSO functionality in Moodle by making use of the
 * Identifier Select feature in OpenID 2.0 to authenticate against fixed (and
 * ideally trusted) provider.  Once enabled, you must configure a fixed server
 * in the OpenID SSO auth settings.  This should only be done when at least one
 * OpenID user has been assigned full administrative rights to avoid being
 * locked out of the site.
 *
 * If you do happen to get locked out of your site, you can override the
 * automatic redirection by appending an 'admin' parameter to the query string
 * when calling login/index.php
 *
 * Eg: http://yourdomain.com/moodle/login/index.php?admin=1
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 */

require_once $CFG->dirroot.'/auth/openid/auth.php';

/**
 * OpenID SSO authentication plugin.
 */
class auth_plugin_openid_sso extends auth_plugin_openid {

    /**
     * Class constructor
     *
     * Assigns default config values and checks for requested actions
     */
    function auth_plugin_openid_sso() {
        global $USER;
        
        $this->authtype = 'openid_sso';
        $this->config = get_config('auth/openid');
        
        // Set some defaults if not already set up
        if (!isset($this->config->openid_sso_url)) {
            set_config('openid_sso_url', '', 'auth/openid');
            $this->config->openid_sso_url='';
        }
        
        // Do we want to disable this plugin to log in as administrator?
        if ($this->manual_override()) {
            $this->config->openid_sso_url='';
        }
        
        if (!isset($this->config->openid_sreg_required)) {
            set_config('openid_sreg_required', 'nickname,email,fullname', 'auth/openid');
            $this->config->openid_sreg_required='nickname,email,fullname';
        }
        
        if (!isset($this->config->openid_sreg_optional)) {
            set_config('openid_sreg_optional', 'country', 'auth/openid');
            $this->config->openid_sreg_optional='country';
        }
        
        if (!isset($this->config->openid_privacy_url)) {
            set_config('openid_privacy_url', '', 'auth/openid');
            $this->config->openid_privacy_url='';
        }
        
        // Define constants used in OpenID lib
        define('OPENID_FIXED_ENDPOINT', '');
    }
    
    /**
     * Returns true if this authentication plugin can change the users'
     * password.
     *
     * Overrides openid plugin's behaviour as SSO won't want multiple openids
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }
    
    /**
     * Confirm the new user as registered.
     *
     * We're not using this in SSO
     *
     * @param string $username (with system magic quotes)
     * @param string $confirmsecret (with system magic quotes)
     */
    function user_confirm($username, $confirmsecret) {
        return false;
    }
    
    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     */
    function config_form($config, $err, $user_fields) {
        global $CFG, $USER;
        include $CFG->dirroot.'/auth/openid/auth_config_sso.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param object object with submitted configuration settings (without system magic quotes)
     */
    function process_config($config) {
        // save settings
        $vars = array(
            'openid_sso_url',
            'openid_sreg_required',
            'openid_sreg_optional',
            'openid_privacy_url'
        );
        
        foreach ($vars as $var) {
            set_config($var, $config->$var, 'auth/openid');
        }
        
        return true;
    }

    /**
     * Hook for overriding behavior of login page.
     * This method is called from login/index.php page for all enabled auth
     * plugins.
     *
     * We're overriding the default login behaviour.
     */
    function loginpage_hook() {
        global $CFG;
        global $frm, $user; // Login page variables
        
        // If the OpenID server isn't defined, don't do anything
        if (empty($this->config->openid_sso_url) || $this->manual_override()) {
            return;
        }
        
        $mode = optional_param('openid_mode', null);
        $allow_append = ($this->config->auth_openid_allow_muliple=='true');
        
        if ($mode == null) {
            // If openid.mode isn't defined, initiate a request
            $this->do_request();
        } else {
            // Otherwise, we'll assume this is a response
            $resp = $this->process_response();
            
            if ($resp !== false) {
                $url = $resp->identity_url;
                
                if (record_exists('openid_urls', 'url', $url)) {
                    // Get the user associated with the OpenID
                    $userid = get_field('openid_urls', 'userid', 'url', $url);
                    $user = get_complete_user_data('id', $userid);
                    
                    // If the user isn't found then there's a database
                    // discrepancy.  We delete this entry and create a new user
                    if (!$user) {
                        delete_records('openid_urls', 'url', $url);
                        $user = $this->_create_account($resp);
                    }
                    
                    // Otherwise, the user is found and we call the optional
                    // on_openid_login function
                    elseif (function_exists('on_openid_login')) {
                        on_openid_login($resp, $user);
                    }
                } else {
                    // Otherwise, create a new account
                    $user = $this->_create_account($resp);
                }
                
                $frm->username = $user->username;
                $frm->password = $user->password;
            }
        }
    }
    
    /**
     * Check if the user wants to override the automatic openid redirect
     *
     * @return boolean
     */
    function manual_override() {
        $admin_override = optional_param('admin', null);
        $username = optional_param('username', null);
        
        if ($admin_override != null || $username != null) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Initiate an OpenID request
     *
     * @param boolean $allow_sreg Default true
     * @param string $process_url Default empty (will use $CFG->wwwroot)
     * @param array $params Array of extra parameters to append to the request
     */
    function do_request($allow_sreg=true, $process_url='', $params=array()) {
        global $CFG;
        
        // Create the consumer instance
        $store = new Auth_OpenID_FileStore($CFG->dataroot.'/openid');
        $consumer = new Auth_OpenID_Consumer($store);
        
        // Create our own endpoint and skip the discovery step.
        $endpoint = new Auth_OpenID_ServiceEndpoint();
        $endpoint->server_url = $this->config->openid_sso_url;
        $endpoint->claimed_id = Auth_OpenID_IDENTIFIER_SELECT;
        $endpoint->type_uris = array(Auth_OpenID_OPENID1_NS);
        $authreq = $consumer->beginWithoutDiscovery($endpoint);
        
        if (!$authreq) {
            error(get_string('auth_openid_login_error', 'auth_openid'));
        } else {
            // Add any simple registration fields to the request
            if ($allow_sreg === true) {
                $sreg_added = false;
                $req = array();
                $opt = array();
                $privacy_url = null;
                
                // Required fields
                if (!empty($this->config->openid_sreg_required)) {
                    $req = explode(',', $this->config->openid_sreg_required);
                    $sreg_added = true;
                }
                
                // Optional fields
                if (!empty($this->config->openid_sreg_optional)) {
                    $opt = explode(',', $this->config->openid_sreg_optional);
                    $sreg_added = true;
                }
                
                // Privacy statement
                if ($sreg_added && !empty($this->config->openid_privacy_url)) {
                    $privacy_url = $this->config->openid_privacy_url;
                }
                
                // We call the on_openid_do_request event handler function if it
                // exists. This is called before the simple registration (sreg)
                // extension is added to allow changes to be made to the sreg
                // data fields if required
                if (function_exists('on_openid_do_request')) {
                    on_openid_do_request($authreq);
                }
                
                // Finally, the simple registration data is added
                if ($sreg_added && !(sizeof($req)<1 && sizeof($opt)<1)) {
                    $sreg_request = Auth_OpenID_SRegRequest::build(
                        $req, $opt, $privacy_url);
                    
                    if ($sreg_request) {
                        $authreq->addExtension($sreg_request);
                    }
                }
            }
            
            // Prepare the remaining components for the request
            if (empty($process_url)) {
                $process_url = $CFG->wwwroot.'/login/index.php';
            }
            
            if (is_array($params) && !empty($params)) {
                $query = '';
                
                foreach ($params as $key=>$val) {
                    $query .= '&'.$key.'='.$val;
                }
                
                $process_url .= '?'.substr($query, 1);
            }
            
            $trust_root = $CFG->wwwroot.'/';
            $_SESSION['openid_process_url'] = $process_url;
            
            // Finally, redirect to the OpenID provider
            if ($authreq->shouldSendRedirect()) {
                $redirect_url = $authreq->redirectURL($trust_root, $process_url);
                
                if (Auth_OpenID::isFailure($redirect_url)) {
                    error($redirect_url->message);
                }
                
                // Otherwise, we want to redirect
                else {
                    redirect($redirect_url);
                }
            }
            
            // or use the post form method if using OpenID 2.0
            else {
                // Generate form markup and render it.
                $form_id = 'openid_message';
                $message = $authreq->getMessage($trust_root, $process_url, false);
                
                // Display an error if the form markup couldn't be generated;
                // otherwise, render the HTML.
                if (Auth_OpenID::isFailure($message)) {
                    error($message);
                }
                
                else {
                    $form_html = $message->toFormMarkup($authreq->endpoint->server_url,
                        array('id' => $form_id), get_string('continue'));
                    echo '<html><head><title>OpenID request</title></head><body onload="document.getElementById(\'',$form_id,'\').submit();" style="text-align: center;"><div style="background: lightyellow; border: 1px solid black; margin: 30px 20%; padding: 5px 15px;"><p>',get_string('openid_redirecting', 'auth_openid'),'</p></div>',$form_html,'</body></html>';
                    exit;
                }
            }
        }
    }
    
    /**
     * Create a new account using simple registration data if available
     *
     * @access private
     * @param object &$resp An OpenID consumer response object
     * @return object The new user
     */
    function _create_account(&$resp) {
        global $CFG, $USER;
        
        $url = $resp->identity_url;
        $password = hash_internal_user_password('openid');
        $server = $resp->endpoint->server_url;
        $sreg_resp = Auth_OpenID_SRegResponse::fromSuccessResponse($resp);
        $sreg = $sreg_resp->contents();
        
        // We'll attempt to use the user's nickname to set their username
        if (isset($sreg['nickname']) && !empty($sreg['nickname']) && !record_exists('users', 'username', $sreg['nickname'])) {
            $username = $sreg['nickname'];
        }
        
        // Otherwise, we'll use their openid url
        else {
            $username = openid_normalize_url_as_username($url);
        }
        
        create_user_record($username, $password, 'openid');
        $user = get_complete_user_data('username', $username);
        openid_append_url($user, $url);
        
        // SREG fullname
        if (isset($sreg['fullname']) && !empty($sreg['fullname'])) {
            $name = openid_parse_full_name($sreg['fullname']);
            $user->firstname = $name['first'];
            $user->lastname = $name['last'];
        }
        
        // SREG email
        if (isset($sreg['email']) && !empty($sreg['email']) && !record_exists('user', 'email', $sreg['email'])) {
            $user->email = $sreg['email'];
        }
        
        // SREG country
        if (isset($sreg['country']) && !empty($sreg['country'])) {
            $country = $sreg['country'];
            $country_code = strtoupper($country);
            $countries = get_list_of_countries();
            
            if (strlen($country) != 2 || !isset($countries[$country_code])) {
                $countries_keys = array_keys($countries);
                $countries_vals = array_values($countries);
                $country_code = array_search($country, $countries_vals);
                
                if ($country_code > 0) {
                    $country_code = $countries_keys[$country_code];
                } else {
                    $country_code = '';
                }
            }
            
            
            if (!empty($country_code)) {
                $user->country = $country_code;
            }
        }
        
        /* We're currently not attempting to get language and timezone values
        // SREG language
        if (isset($sreg['language']) && !empty($sreg['language'])) {
        }
        
        // SREG timezone
        if (isset($sreg['timezone']) && !empty($sreg['timezone'])) {
        }
        */
        
        if (function_exists('on_openid_create_account')) {
            on_openid_create_account($resp, $user);
        }
        
        update_record('user', $user);
        $user = get_complete_user_data('id', $user->id);
        
        // Redirect the user to their profile page if not set up properly
        if (!empty($user) && user_not_fully_set_up($user)) {
            $USER = clone($user);
            $urltogo = $CFG->wwwroot.'/user/edit.php';
            redirect($urltogo);
        }
        
        return $user;
    }
}

?>
