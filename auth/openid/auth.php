<?php

/**
 * Authentication Plugin: OpenID Authentication
 *
 * This plugin provides standard OpenID consumer functionality in Moodle.
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once $CFG->libdir.'/authlib.php';
require_once $CFG->dirroot.'/auth/openid/lib.php';

// Append the OpenID directory to the include path and include relevant files
set_include_path(get_include_path().PATH_SEPARATOR.$CFG->libdir.'/openid/');

// Required files (library)
require_once 'Auth/OpenID/Consumer.php';
require_once 'Auth/OpenID/FileStore.php';
require_once 'Auth/OpenID/SReg.php';

// Include the custom event script if it exists
if (file_exists($CFG->dirroot.'/auth/openid/event.php')) {
    include $CFG->dirroot.'/auth/openid/event.php';
}

/**
 * OpenID authentication plugin.
 */
class auth_plugin_openid extends auth_plugin_base {

    /**
     * Class constructor
     *
     * Assigns default config values and checks for requested actions
     */
    function auth_plugin_openid() {
        global $USER;
        
        $this->authtype = 'openid';
        $this->config = get_config('auth/openid');
        
        // Set some defaults if not already set up
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
        
        if (!isset($this->config->openid_require_greylist_confirm)) {
            set_config('openid_require_greylist_confirm', 'true', 'auth/openid');
            $this->config->openid_require_greylist_confirm='true';
        }
        
        if (!isset($this->config->auth_openid_allow_account_change)) {
            set_config('auth_openid_allow_account_change', 'false', 'auth/openid');
            $this->config->auth_openid_allow_account_change='true';
        }
        
        if (!isset($this->config->auth_openid_allow_muliple)) {
            set_config('auth_openid_allow_muliple', 'true', 'auth/openid');
            $this->config->auth_openid_allow_muliple='true';
        }
        
        // Define constants used in OpenID lib
        define('OPENID_USE_IDENTIFIER_SELECT', 'false');
    }
    
    /**
     * Returns true if this authentication plugin can change the users'
     * password.
     *
     * Cheeky hack to place OpenID configuration in the user's main profile
     * page.
     *
     * Takes advantage of the fact that /user/view.php checks the user's
     * authentication class (ie: this one!) to see if it offers the ability
     * to change passwords.  This plugin can't change passwords so we return
     * false but we also use it as the hook to display the form.
     *
     * @return bool
     */
    function can_change_password() {
        global $CFG, $USER;
        // We're only doing this if the calling page is the user's main profile
        // page and we know $user is defined at that point.
        global $user;
        
        if (is_enabled_auth('openid')) {
            $in_user_view = ($_SERVER['SCRIPT_FILENAME'] == $CFG->dirroot.'/user/view.php');
            $allow_append = ($this->config->auth_openid_allow_muliple=='true');
            
            if ($in_user_view && $allow_append) {
                include $CFG->dirroot.'/auth/openid/user_profile.html';
            }
        }
        
        return false;
    }
    
    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    function can_confirm() {
        return true;
    }

    /**
     * Confirm the new user as registered.
     *
     * @param string $username (with system magic quotes)
     * @param string $confirmsecret (with system magic quotes)
     */
    function user_confirm($username, $confirmsecret) {
        $user = get_complete_user_data('username', $username);

        if (!empty($user)) {
            if ($user->confirmed) {
                return AUTH_CONFIRM_ALREADY;

            } else if ($user->auth != $this->authtype) {
                return AUTH_CONFIRM_ERROR;

            } else if ($user->secret == stripslashes($confirmsecret)) {   // They have provided the secret key to get in
                if (!set_field('user', 'confirmed', 1, 'id', $user->id)) {
                    return AUTH_CONFIRM_FAIL;
                }
                if (!set_field('user', 'firstaccess', time(), 'id', $user->id)) {
                    return AUTH_CONFIRM_FAIL;
                }
                return AUTH_CONFIRM_OK;
            }
        } else {
            return AUTH_CONFIRM_ERROR;
        }
    }

    /**
     * Delete user openid records from database
     *
     * @param object $user       Userobject before delete    (without system magic quotes)
     */
    function user_delete($olduser) {
        delete_records('openid_urls', 'userid', $olduser->id);
    }

    /**
     * This is the primary method that is used by the authenticate_user_login()
     * function in moodlelib.php. This method should return a boolean indicating
     * whether or not the username and password authenticate successfully.
     *
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        // This plugin doesn't use usernames and passwords
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
        include $CFG->dirroot.'/auth/openid/auth_config.html';
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     * @param object object with submitted configuration settings (without system magic quotes)
     * @param array $err array of error messages
     */
    function validate_form(&$form, &$err) {
        //override if needed
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param object object with submitted configuration settings (without system magic quotes)
     */
    function process_config($config) {
        $page = optional_param('page', '');
        
        if ($page == 'users') {
            $vars = array(
                'auth_openid_allow_account_change',
                'auth_openid_allow_muliple',
                'openid_require_greylist_confirm'
            );
        } elseif ($page == 'sreg') {
            $vars = array(
                'openid_sreg_required',
                'openid_sreg_optional',
                'openid_privacy_url'
            );
        } elseif ($page == 'servers') {
            $vars = array();
            $add = optional_param('add_server', null);
            
            if ($add != null) {
                $record = new object();
                $record->server = required_param('openid_add_server');
                $record->listtype = optional_param('openid_add_listtype', 0, PARAM_INT);
                
                if ($record->listtype != OPENID_WHITELIST && $record->listtype != OPENID_BLACKLIST) {
                    $record->listtype = OPENID_GREYLIST;
                }
                
                if (!empty($record->server) && !record_exists('openid_servers', 'server', $record->server)) {
                    insert_record('openid_servers', $record);
                }
            } else {
                $servers = optional_param('servers', array());
                
                foreach ($servers as $id=>$val) {
                    $id = intval($id);
                    $val = intval($val);
                    
                    if ($id < 1) {
                        continue;
                    }
                    
                    // If we encounter a 'delete' request
                    if ($val < 1) {
                        delete_records('openid_servers', 'id', $id);
                        continue;
                    }
                    
                    // Otherwise, force a valid value (default 'GREYLIST')
                    if ($val != OPENID_WHITELIST && $val != OPENID_BLACKLIST) {
                        $val = OPENID_GREYLIST;
                    }
                    
                    // And update record
                    $record = new object();
                    $record->id = $id;
                    $record->listtype = $val;
                    update_record('openid_servers', $record);
                }
            }
        }
        
        foreach ($vars as $var) {
            set_config($var, $config->$var, 'auth/openid');
            $this->config->$var = $config->$var;
        }
        
        return false;
    }

    /**
     * Hook for overriding behavior of login page.
     * This method is called from login/index.php page for all enabled auth
     * plugins.
     *
     * We're overriding the default login behaviour when login is attempted or
     * an OpenID response is received.  We also provide our own login form if
     * an alternate login url hasn't already been defined.  This doesn't alter
     * the site's configuration value.
     */
    function loginpage_hook() {
        global $CFG;
        global $frm, $user; // Login page variables
        
        $openid_url = optional_param('openid_url', null);
        $mode = optional_param('openid_mode', null);
        $allow_append = ($this->config->auth_openid_allow_muliple=='true');
        
        // We need to use our OpenID login form
        if (empty($CFG->alternateloginurl)) {
            $CFG->alternateloginurl = $CFG->wwwroot.'/auth/openid/login.php';
        }
        
        if ($mode == null && $openid_url != null) {
            // If we haven't received a response, then initiate a request
            $this->do_request();
        } elseif ($mode != null) {
            // If openid.mode is set then we'll assume this is a response
            $resp = $this->process_response();
            
            if ($resp !== false) {
                $url = $resp->identity_url;
                $server = $resp->endpoint->server_url;
                
                if (openid_server_is_blacklisted($server)) {
                    error(get_string('auth_openid_server_blacklisted',
                                     'auth_openid', $server));
                } elseif (record_exists('openid_urls', 'url', $url)) {
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
        $openid_url = optional_param('openid_url', null);
        $authreq = $consumer->begin($openid_url);
        
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
            // If the server is blacklisted
            if (openid_server_is_blacklisted($authreq->endpoint->server_url)) {
                error(get_string('auth_openid_server_blacklisted',
                               'auth_openid', $authreq->endpoint->server_url));
            }
            
            // If this is an OpenID 1.x request, redirect the user
            elseif ($authreq->shouldSendRedirect()) {
                $redirect_url = $authreq->redirectURL($trust_root, $process_url);
                
                // If the redirect URL can't be built, display an error message.
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
     * Process an OpenID response
     *
     * By default, this method uses the error() function to display errors. This
     * is a terminal function so if you want to display errors inline using the
     * notify() function you will need to pass true to the $notify_errors
     * argument
     *
     * @param boolean $notify_errors Default true
     * @return mixed Successful response object or false
     */
    function process_response($notify_errors=false) {
        global $CFG;
        
        // Create the consumer instance
        $store = new Auth_OpenID_FileStore($CFG->dataroot.'/openid');
        $consumer = new Auth_OpenID_Consumer($store);
        $resp = $consumer->complete($_SESSION['openid_process_url']);
        unset($_SESSION['openid_process_url']);
        
        // Act based on response status
        switch ($resp->status) {
        case Auth_OpenID_SUCCESS:
            // Auth succeeded
            return $resp;
        
        case Auth_OpenID_CANCEL:
            // Auth cancelled by user.
            $msg = get_string('auth_openid_user_cancelled', 'auth_openid');
            
            if ($notify_errors) {
                notify($msg);
            } else {
                error($msg);
            }
            
            break;
        
        case Auth_OpenID_FAILURE:
            // Auth failed for some reason
            $msg = openid_get_friendly_message($resp->message);
            $msg = get_string('auth_openid_login_failed', 'auth_openid', $msg);
            
            if ($notify_errors) {
                notify($msg);
            } else {
                error($msg);
            }
        }
        
        return false;
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
        
        $glconfirm = ($this->config->openid_require_greylist_confirm == 'true');
        
        if ($glconfirm && !openid_server_is_whitelisted($server)) {
            $secret = random_string(15);
            set_field('user', 'secret', $secret, 'id', $user->id);
            $user->secret = $secret;
            set_field('user', 'confirmed', 0, 'id', $user->id);
            $user->confirmed = 0;
            openid_send_confirmation_email($user);
        }
        
        return $user;
    }
}

?>
