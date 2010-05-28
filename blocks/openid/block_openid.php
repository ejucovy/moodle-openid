<?php

/**
 * OpenID block
 *
 * This block provides a simple login form for your site's side bars.  It
 * displays content appropriate for the user's state so, for example, it will
 * direct the user the the actions.php script if they are logged in and allowed
 * to amend their account or the login form if they aren't logged in.
 *
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package openid
 **/

class block_openid extends block_base {
    function init() {
        $this->title = get_string('block_title','auth_openid');
        $this->version = 2007090500;
    }
    
    function applicable_formats() {
        return array('site' => true);
    }

    function get_content() {
        global $USER, $CFG;
        
        // We don't want to show this block if OpenID auth isn't enabled
        if (!is_enabled_auth('openid')) {
            return '';
        }
        
        $config = get_config('auth/openid');
        $user_is_openid = ($USER->auth == 'openid');
        
        // Check to see if the box should be displayed to a logged in user
        if ($USER->id > 0) {
            // We don't want to allow admin or guest users to be changed
            if ($USER->username == 'admin' || $USER->username == 'guest') {
                return '';
            }
            
            if (!isset($config->auth_openid_allow_account_change)) {
                $config->auth_openid_allow_account_change='true';
            }
            
            if (!isset($config->auth_openid_allow_muliple)) {
                $config->auth_openid_allow_muliple='true';
            }
            
            $allow_change = ($config->auth_openid_allow_account_change=='true');
            $allow_append = ($config->auth_openid_allow_muliple=='true');
            
            if (($user_is_openid && !$allow_append) || (!$user_is_openid && !$allow_change)) {
                return '';
            }
        }
        
        if ($this->content !== NULL) {
            return $this->content;
        }
        
        $this->content->footer = '';
        $this->content->text = '';
        $username = get_moodle_cookie() === 'nobody' ? '' : get_moodle_cookie();
        
        $user=get_complete_user_data('username', $username);
        
        if ($user->auth != 'openid' || $USER->id > 0) {
            $username='';
        }
        
        if ($USER->id > 0) {
            $endpoint = $CFG->wwwroot.'/auth/openid/actions.php';
        } else {
            $endpoint = $CFG->wwwroot.'/login/index.php';
        }
        
        $this->content->text .= '
            <style type="text/css">
            input.openid_login {
                background: url('.$CFG->wwwroot.'/auth/openid/icon.gif) no-repeat;
                background-color: #fff;
                background-position: 0 50%;
                color: #000;
                padding-left: 18px;
            }
            </style>
            <form class="loginform" name="login" method="post" action="'.$endpoint.'">
                <table align="center" cellpadding="2" cellspacing="0" class="logintable">
        ';
        
        if ($USER->id > 0) {
            $this->content->text .= '<tr><td class="c0 r0" colspan="2"><small>';
            
            if ($user_is_openid) {
                $this->content->text .= '<input type="hidden" name="openid_action" value="append" />';
                $this->content->text .= get_string('append_text',
                                                   'auth_openid');
            } else {
                $this->content->text .= '<input type="hidden" name="openid_action" value="change" />';
                $this->content->text .= get_string('change_text',
                                                   'auth_openid');
            }
            
            $this->content->text .= '</small></td></tr>';
        }
        
        $this->content->text .= '
                <tr>
                    <td class="c0 r1" colspan="2">
                        <input class="openid_login" type="text" name="openid_url" size="18" value="" />
                    </td>
                </tr>
                <tr>
                    <td colspan="2" class="c1 r2" align="right">
                        <a href="http://openid.net/"><small>'.get_string('whats_this', 'auth_openid').'</small></a>
                        <input type="submit" value="'.get_string('login').'" />
                    </td>
                </tr>
                <tr>
                    <td colspan="2" class="c1 r2" align="right">
                        <a href="'.$CFG->wwwroot.'/auth/openid/fallback.php"><small>'.get_string('provider_offline', 'auth_openid').'</small></a>
                    </td>
            </table>
        </form>
        ';
        return $this->content;
    }
}
?>