<?php

/**
 * OpenID actions
 *
 * This file contains any non-authentication actions such as adding OpenIDs to
 * an account and changing an account to OpenID
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package openid
 **/

require_once("../../config.php");

// We don't want to allow use of this script if OpenID auth isn't enabled
if (!is_enabled_auth('openid')) {
    error("OpenID not enabled!");
}

require_login();

$action = optional_param('openid_action', '');
$url = optional_param('openid_url', null);
$delete_urls = optional_param('delete_urls', array());
$mode = optional_param('openid_mode', null);
$confirm = optional_param('confirm_action', false, PARAM_BOOL);
$cancel = optional_param('cancel_action', false, PARAM_BOOL);
$authplugin = get_auth_plugin('openid');

switch ($action) {

// Change an account type to OpenID
case 'change':
    if ($mode != null) {
        // We need to print a confirmation message before proceeding
        $resp = $authplugin->process_response($_GET, true);
        
        if ($resp !== false) {
            $url = $resp->identity_url;
            $file = 'confirm_change.html';
        }
    } elseif ($confirm) {
        if (!confirm_sesskey()) {
            error('Bad Session Key');
        } else {
            openid_change_user_account($USER, $url);
        }
    } elseif ($cancel) {
        error(get_string('action_cancelled', 'auth_openid'));
    } elseif ($url != null) {
        if (openid_already_exists($url)) {
            error(get_string('auth_openid_url_exists', 'auth_openid', $url));
        } else {
            $params['openid_action'] = 'change';
            $authplugin->do_request(false, $CFG->wwwroot.'/auth/openid/actions.php', $params);
        }
    }
    
    break;
    
// Append an OpenID url to an account
case 'append':
    if ($mode != null) {
        // We need to print a confirmation message before proceeding
        $resp = $authplugin->process_response($_GET, true);
        
        if ($resp !== false) {
            $url = $resp->identity_url;
            $file = 'confirm_append.html';
        }
    } elseif ($confirm) {
        if (!confirm_sesskey()) {
            error('Bad Session Key');
        } else {
            openid_append_url($USER, $url);
        }
    } elseif ($cancel) {
        error(get_string('action_cancelled', 'auth_openid'));
    } elseif ($url != null) {
        if (openid_already_exists($url)) {
            error(get_string('auth_openid_url_exists', 'auth_openid', $url));
        } else {
            $params['openid_action'] = 'append';
            $authplugin->do_request(false, $CFG->wwwroot.'/auth/openid/actions.php', $params);
        }
    }
    
    break;
    
// Delete OpenIDs from an account
case 'delete':
    // Prevent users from deleting all their OpenIDs!
    if (sizeof($delete_urls) >= count_records('openid_urls', 'userid', $USER->id)) {
        error(get_string('cannot_delete_all', 'auth_openid'));
    }
    
    if ($confirm && is_array($delete_urls)) {
        foreach ($delete_urls as $url_id) {
            $url_id = intval($url_id);
            delete_records('openid_urls', 'id', $url_id, 'userid', $USER->id);
        }
    } elseif ($cancel) {
        error(get_string('action_cancelled', 'auth_openid'));
    } elseif (is_array($delete_urls)) {
        $file = 'confirm_delete.html';
    }
    
    break;
    
// Reject any other action
default:
    error('Unrecognised action');
}

if (isset($file)) {
    // Define variables used in page
    if (!$site = get_site()) {
        error("No site found!");
    }

    if (empty($CFG->langmenu)) {
        $langmenu = "";
    } else {
        $currlang = current_language();
        $langs    = get_list_of_languages();
        $langlabel = '<span class="accesshide">'.get_string('language').':</span>';
        $langmenu = popup_form ("$CFG->httpswwwroot/login/index.php?lang=", $langs, "chooselang", $currlang, "", "", "", true, 'self', $langlabel);
    }

    $loginsite = get_string("loginsite");

    print_header("$site->fullname: $loginsite", $site->fullname, $loginsite, $focus, 
			 '', true, '<div class="langmenu">'.$langmenu.'</div>'); 

    include $file;

    print_footer();
} else {
    $urltogo = $CFG->wwwroot.'/user/view.php';
    redirect($urltogo);
}

?>
