<?php

/**
 * OpenID login form
 *
 * This file is principally a copy of the relevant parts of the Moodle
 * /login/index.php file from the default installation.
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

/// Define variables used in page
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

/// Generate the login page with forms

    if ($session_has_timed_out) {
        $errormsg = get_string('sessionerroruser', 'error');
    }

    if (get_moodle_cookie() == '') {   
        set_moodle_cookie('nobody');   // To help search for cookies
    }
    
    if (empty($frm->username) && $authsequence[0] != 'shibboleth') {  // See bug 5184
        $frm->username = get_moodle_cookie() === 'nobody' ? '' : get_moodle_cookie();
        $frm->password = "";
    }
    
    if (!empty($frm->username)) {
        $focus = "password";
    } else {
        $focus = "username";
    }

    if (!empty($CFG->registerauth) or is_enabled_auth('none') or !empty($CFG->auth_instructions)) {
        $show_instructions = true;
    } else {
        $show_instructions = false;
    }

    print_header("$site->fullname: $loginsite", $site->fullname, $loginsite, $focus, 
			 '', true, '<div class="langmenu">'.$langmenu.'</div>'); 

    include 'login_form.html';
    
    print_footer();
    
?>
