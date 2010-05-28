<?php

/**
 * OpenID module/auth library functions
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package openid
 */

define('OPENID_GREYLIST', 0);
define('OPENID_BLACKLIST', 1);
define('OPENID_WHITELIST', 2);

// Create the store directories if they don't exist
$store_dirs = array('openid/associations', 'openid/nonces', 'openid/temp');

foreach ($store_dirs as $store_dir) {
    if (!file_exists($CFG->dataroot.'/'.$store_dir) && !make_upload_directory($store_dir)) {
        error('OpenID store not writable!  Please refer to documentation.');
    }
}

/**
 * fnmatch function is not available on non-posix system.  This should be a
 * suitable replacement for our purposes (ie: wildcard pattern matching for
 * server addresses like '*.php.net')
 */
if (!function_exists('fnmatch')) {
    function fnmatch($pattern, $string) {
        return @preg_match(
            '/^' . strtr(addcslashes($pattern, '/\\.+^$(){}=!<>|'),
            array('*' => '.*', '?' => '.?')) . '$/i', $string
        );
    }
}

/**
 * Check if an OpenID server is whitelisted
 *
 * @param string $server
 * @return boolean
 */
function openid_server_is_whitelisted($server) {
    $servers = get_records('openid_servers', 'listtype', OPENID_WHITELIST);
    
    foreach ($servers as $op) {
        if (true === fnmatch($op->server, $server)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if an OpenID server is blacklisted
 *
 * @param string $server
 * @return boolean
 */
function openid_server_is_blacklisted($server) {
    $servers = get_records('openid_servers', 'listtype', OPENID_BLACKLIST);
    
    foreach ($servers as $op) {
        if (true === fnmatch($op->server, $server)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Attempt to parse first and last name components from a full name
 *
 * OpenID provides a fullname as part of the simple registration extension;
 * Moodle requires a separate first and last name.  This is an attempt at
 * parsing the second items from the first.  We're not guaranteeing success
 * here but merely splitting the fullname at the first space to try and make
 * registration a little easier.
 *
 * The returned associative array contains the following keys:
 * - first
 * - last
 *
 * @param string $fullname The full name as returned in the OpenID response
 * @return array An associative array of the name components
 */
function openid_parse_full_name($fullname) {
    $name = array('first'=>'','last'=>'');
    
    if (empty($fullname)) {
        return $name;
    }
    
    // If fullname doesn't contain at least 1 space, let's take a lucky
    // guess that it's a firstname.
    if (strpos($fullname, ' ') === false) {
        $name['first'] = $fullname;
    } else {
        $parts = explode(' ', $fullname, 2);
        $name['first'] = $parts[0];
        $name['last'] = $parts[1];
    }
    
    return $name;
}

/**
 * Get a friendlier version of a message if available
 *
 * This is used to replace a hard-coded Janrain messages with our own, if
 * it's been defined in a language file.  To replace a particular message,
 * the message should be converted to lower case; have spaces replaced with
 * underscores and remove anything except alphanumeric chars and
 * underscores.  Finally, 'auth_openid_' should be prepended.  This is then
 * the name of the languages string.
 *
 * For example:
 * Nonce missing from store
 *
 * becomes:
 * $string['auth_openid_nonce_missing_from_store']='My message';
 *
 * To ensure your changes aren't overwritten in a future update, you should
 * define all custom error strings in a local language file as described in
 * the Moodle documentation
 *
 * If the string isn't defined, the original message is returned intact.
 *
 * @param string $message The original message
 * @return string The resulting message
 */
function openid_get_friendly_message($message) {
    $msgdef = strtolower($message);
    $msgdef = ereg_replace(' ', '_', $msgdef);
    $msgdef = ereg_replace('[^0-9a-z_]', '', $msgdef);
    $msgdef = 'auth_openid_'.$msgdef;
    $msg = get_string($msgdef, 'auth_openid');
    
    if ($msg != '[['.$msgdef.']]') {
        return $msg;
    } else {
        return $message;
    }
}

/**
 * Send email to specified user with confirmation text and activation link.
 *
 * This function is largely a copy of the Moodle send_confirmation_email()
 * function with changes to suit the openid auth plugin.
 *
 * @uses $CFG
 * @param user $user A {@link $USER} object
 * @return bool|string Returns "true" if mail was sent OK, "emailstop" if email
 * was blocked by user and "false" if there was another sort of error.
 */
function openid_send_confirmation_email($user) {
    global $CFG;

    $site = get_site();
    $from = get_admin();

    $data = new object();
    $data->firstname = fullname($user);
    $data->sitename = format_string($site->fullname);
    $data->admin = fullname($from) .' ('. $from->email .')';

    $subject = get_string('emailconfirmationsubject', '', format_string($site->fullname));

    $data->link = $CFG->wwwroot .'/auth/openid/confirm.php?data='. $user->secret .'|'. urlencode($user->username);
    $message     = get_string('emailconfirmation', '', $data);
    $messagehtml = text_to_html(get_string('emailconfirmation', '', $data), false, false, true);

    $user->mailformat = 1;  // Always send HTML version as well

    return email_to_user($user, $from, $subject, $message, $messagehtml);
}

/**
 * Send email to specified user with fallback text and link.
 *
 * This function is largely a copy of the Moodle send_confirmation_email()
 * function with changes to suit the openid auth plugin.
 *
 * @uses $CFG
 * @param user $user A {@link $USER} object
 * @return bool|string Returns "true" if mail was sent OK, "emailstop" if email
 * was blocked by user and "false" if there was another sort of error.
 */
function openid_send_fallback_email($user, $openid_url) {
    global $CFG;

    $site = get_site();
    $from = get_admin();

    $data = new object();
    $data->firstname = fullname($user);
    $data->sitename = format_string($site->fullname);
    $data->admin = fullname($from) .' ('. $from->email .')';
    $data->openid_url = $openid_url;

    $subject = get_string('emailfallbacksubject', 'auth_openid',
                          format_string($site->fullname));

    $data->link = $CFG->wwwroot .'/auth/openid/fallback.php?data='. $user->secret .'|'. urlencode($user->username);
    $message     = get_string('emailfallback', 'auth_openid', $data);
    $messagehtml = text_to_html(get_string('emailfallback', 'auth_openid',
                                $data), false, false, true);

    $user->mailformat = 1;  // Always send HTML version as well

    return email_to_user($user, $from, $subject, $message, $messagehtml);
}

/**
 * Checks if an OpenID URL is in the database as either a primary username in
 * the user table or as a url in the openid_urls table
 *
 * @param string $openid_url
 * @return boolean
 */
function openid_already_exists($openid_url) {
    return record_exists('openid_urls', 'url', $openid_url);
}

/**
 * Changes a non-OpenID user's account to OpenID
 *
 * @param object $user
 * @param string $openid_url
 * @return boolean
 */
function openid_change_user_account(&$user, $openid_url) {
    // We don't want to allow admin or guest users to be changed
    if ($user->username == 'admin' || $user->username == 'guest') {
        error('Cannot change that user!');
    }
    
    $config = get_config('auth/openid');
    $allow_change = ($config->auth_openid_allow_account_change=='true');
    $user = get_complete_user_data('id', $user->id);
    
    if (empty($user)) {
        error('Not logged in');
        return false;
    }
    
    if (!$allow_change) {
        error('Cannot change accounts');
        return false;
    }
    
    if (openid_already_exists($openid_url)) {
        error(get_string('auth_openid_url_exists', 'auth_openid', $openid_url));
        return false;
    }
    
    if ($user->auth != 'openid') {
        $user->auth = 'openid';
        
        if (update_record('user', $user) !== false) {
            openid_append_url($user, $openid_url);
            return true;
        }
    }
    
    return false;
}

/**
 * Appends an OpenID url to a user's account
 *
 * @param object $user
 * @param string $openid_url
 * @return boolean
 */
function openid_append_url($user, $openid_url) {
    $config = get_config('auth/openid');
    $allow_append = ($config->auth_openid_allow_muliple=='true');
    $user = get_complete_user_data('id', $user->id);
    
    if (empty($user)) {
        error('Not logged in');
        return false;
    }
    
    if (count_records('openid_urls', 'userid', $user->id)>0 && !$allow_append) {
        error('Cannot add additional OpenIDs');
        return false;
    }
    
    if (openid_already_exists($openid_url)) {
        error(get_string('auth_openid_url_exists', 'auth_openid', $openid_url));
        return false;
    }
    
    if ($user->auth == 'openid') {
        $record = new object();
        $record->userid = $user->id;
        $record->url = $openid_url;
        
        if (insert_record('openid_urls', $record) !== false) {
            return true;
        }
    }
    
    return false;
}

/**
 * Normalize an OpenID url for use as a username in the users table
 *
 * The function will ensure the returned username is not present in the
 * database.  It will do this by incrementing an appended number until the
 * username is not found.
 *
 * @param string $openid_url
 * @return string
 */
function openid_normalize_url_as_username($openid_url) {
    $username = eregi_replace('[^a-z0-9]', '', $openid_url);
    $username = substr($username, 0, 90); // Keep it within limits of schema
    $username_tmp = $username;
    $i = 1;
    
    while (record_exists('user', 'username', $username)) {
        $username = $username_tmp.$i++;
    }
    
    return $username;
}

?>
