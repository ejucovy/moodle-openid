<?php

/**
 * OpenID language file for Moodle
 *
 * This file contains the strings used by the OpenID authentication plugin. 
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 * @package openid
 */

global $CFG;

// Module strings
$string['modulename'] = 'OpenID';
$string['whats_this'] = 'What\'s this?';
$string['provider_offline'] = 'Help, my provider is offline!';

// Block strings
$string['block_title'] = 'OpenID';
$string['append_text'] = 'You can add another OpenID to your account by entering another OpenID here';
$string['change_text'] = 'You can change your account to OpenID by entering your OpenID here';

// Login strings
$string['openid_enabled'] = 'We are OpenID Enabled';
$string['openid_text'] = 'You can login or signup here with your OpenID url.';
$string['openid_note'] = 'Already got an account here and want to sign in with your new OpenID?  Just enter your OpenID once you\'ve logged in as normal and we\'ll link your account to your OpenID';
$string['openid_note_user'] = 'To create a separate account with your OpenID, you must <a href=\"'.$CFG->wwwroot.'/login/logout.php?sesskey='.sesskey().'\">'.get_string('logout').'</a> first.';
$string['openid_redirecting'] = 'You are about to be redirected to your OpenID provider.  If you are not redirected automatically, please click the continue button below.';

// Fallback strings
$string['fallback_text'] = 'When you enter a registered OpenID here, we will send a one-time link to the email address associated with that OpenID to allow you to log in without having to authenticate with your OpenID provider.  This may be useful if your OpenID provider is offline for some reason, or if you unregistered with your provider and forgot to update your account.';
$string['fallback_message_sent'] = 'An email was sent to the address registered to that OpenID with a link to a one-time login page.';
$string['emailfallbacksubject'] = '$a: One-time login';
$string['emailfallback'] = 'Hi $a->firstname,

A one-time login has been requested at \'$a->sitename\'
for your OpenID ($a->openid_url).

To login without needing to access your OpenID provider,
please go to this web address:

$a->link

In most mail programs, this should appear as a blue link
which you can just click on.  If that doesn\'t work,
then cut and paste the address into the address
line at the top of your web browser window.

This link will only work once and is time-limited to 30
minutes from the time it was requested.

If you need help, please contact the site administrator,
$a->admin';

// Action strings
$string['confirm_sure'] = 'Are you sure you want to do this?';
$string['confirm_append'] = 'You are about to add the identity, $a to your account.  '.$string['confirm_sure'];
$string['confirm_change'] = 'You are about to change your account to OpenID using the identity $a.  This will change your login details and prevent you from logging in using your current method.  '.$string['confirm_sure'];
$string['confirm_delete'] = 'You are about to delete the following identities from your account:';
$string['action_cancelled'] = 'Action cancelled.  No changes have been made to your account.';
$string['cannot_delete_all'] = 'Sorry, but you cannot delete all of your openids.';

// Profile strings
$string['openid_manage'] = 'Manage your OpenIDs';
$string['add_openid'] = 'Add OpenID to your account';
$string['openid_main'] = '(Main OpenID)';
$string['delete_selected'] = 'Delete selected';

// Error strings
$string['auth_openid_multiple_disabled'] = 'Sorry but you can no longer log in with multiple OpenIDs on this site.  Please contact the site owner.';
$string['auth_openid_server_blacklisted'] = 'Sorry, we do not accept registrations from your OpenID server, $a';
$string['auth_openid_url_exists'] = 'Sorry but the OpenID, $a, is already registered here';
$string['auth_openid_user_cancelled'] = 'Authentication cancelled by user';
$string['auth_openid_login_failed'] = 'Authentication failed. Server reported: $a';
$string['auth_openid_login_error'] = 'An error occurred while authenticating with your OpenID provider. Please check your OpenID URL and try again.';
$string['auth_openid_filestore_not_writeable'] = 'I couldn\'t write to the file store directory. Please ensure the directories in moodle/auth/openid/store/ are writable and try again';

// Tabs
$string['openid_tab_users'] = 'Users';
$string['openid_tab_sreg'] = 'Simple Registration Extension';
$string['openid_tab_servers'] = 'Servers';

// Config strings
$string['auth_openid_sso_settings'] = 'OpenID Single Sign-On (SSO) settings';
$string['auth_openid_sso_description'] = 'This authentication plugin, once configured, functions as the sole authentication system on your site.  This may be useful if you are planning on using OpenID as an internal identity provider.<br /><br /><strong>Important: Before entering a server URL, please ensure you have at least one user registered against it with administrative permissions (Users-&gt;Permissions-&gt;Assign global roles-&gt;Administrator). If you need to log back in with a normal username and password once this plugin is enabled, you can override it by adding the query parameter \'admin\' to your login URL (eg: http://yoursite/moodle/login/index.php?admin=true).</strong>';
$string['auth_openid_sso_op_url_key'] = 'Server URL';
$string['auth_openid_sso_op_url'] = 'This is the URL of the OpenID server you want to use as your SSO provider.';
$string['auth_openid_sreg_settings'] = 'Simple Registration Extension (SREG) settings';
$string['auth_openid_sreg_description'] = 'OpenID Simple Registation is an extension to the OpenID Authentication protocol that allows for very light-weight profile exchange. It is designed to pass eight commonly requested pieces of information when an End User goes to register a new account with a web service.<br /><br />Fields <a href=\"http://openid.net/specs/openid-simple-registration-extension-1_0.html\">defined by the specification</a> are: nickname, email, fullname, dob, gender, postcode, country, language and timezone. This plugin currently processes: nickname, email, fullname and country';
$string['auth_openid_sreg_required_key'] = 'Required fields';
$string['auth_openid_sreg_required'] = 'Comma separated list of fields.  By adding fields to this list you are indicating that the user will not be able to complete registration without them and the OpenID provider may be able to speed the registration process by returning them.  <em>Required fields are not guaranteed to be returned by an OpenID provider.</em>';
$string['auth_openid_sreg_optional_key'] = 'Optional fields';
$string['auth_openid_sreg_optional'] = 'Comma separated list of fields.  By adding fields to this list you are indicating that the user will be able to register without them but they will be used if the OpenID provider sends them.';
$string['auth_openid_privacy_url_key'] = 'Privacy policy';
$string['auth_openid_privacy_url'] = 'If you publish a privacy policy online, enter the full URL here so OpenID users can read it.  <em>Only used if SREG fields are specified</em>';
$string['auth_openid_user_settings'] = 'OpenID User settings';
$string['auth_openid_user_description'] = 'Settings to allow or prevent users from carrying out certain actions';
$string['auth_openid_allow_account_change_key'] = 'Allow users to change their account type to OpenID by authenticating with an OpenID provider?';
$string['auth_openid_allow_muliple_key'] = 'Allow users to register more than one identity for each account?';
$string['openid_require_greylist_confirm_key'] = 'Require users of non-whitelisted servers to confirm their registration? <small>This is only used where an application would otherwise be completed automatically without human intervention (eg: where Simple Registration Data covers the minimum registration requirements)</small>';
$string['auth_openid_servers_settings'] = 'Server settings';
$string['auth_openid_servers_description'] = 'Manage your list of OpenID servers which are automatically allowed or blocked. You can use wilcards such as *.myopenid.com.<br /><br /><small><em>If you have unchecked the option to require users of non-whitelisted servers to confirm their registration then servers set as \'confirm\' will behave like servers set as \'allow\'.</small>';

?>
