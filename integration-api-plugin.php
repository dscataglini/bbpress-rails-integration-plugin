<?php
class BBIntegrationApiPlugin
{
    public static $api = null;

    public function __construct() {
    }

    function BBIntegrationApiPlugin() {
    }
	  
	
    /*
     * Do simple caching of the IntegrationApi instance.
     * There's probably a simpler way to do this.
     */
    function api() {
        if (!self::$api) {
			self::$api = new BBIntegrationApi(bb_get_option('i_api_api_url'));
		}
      	return self::$api;
    }

    /*************************************************************
     * Plugin hooks
     *************************************************************/
    
    /*
     * Add options for this plugin to the database.
     */
    function initialize_options() {
	
	    if (bb_current_user_can('manage_options')) {
			bb_update_option('i_api_auto_create_user', false); // Should a new user be created automatically if not already in the bbPress database?
			bb_update_option('i_api_api_url', 'http://localhost:3000/integration_api/'); // Should a new user be created automatically if not already in the bbPress database?
			bb_update_option('i_api_user_username',  ''); // How do you store the username in your Rails app?
			bb_update_option('i_api_user_firstname', ''); // How do you store the first name in your Rails app?
			bb_update_option('i_api_user_lastname',  ''); // How do you store the last name in your Rails app?
			bb_update_option('i_api_user_email',     ''); // How do you store the user email in your Rails app?
			bb_update_option('i_api_user_website',   ''); // How do you store the user's website in your Rails app?
			bb_update_option('i_api_single_signon', false); // Automatically detect if a user is logged in?
			bb_update_option('i_api_user_nickname', '');
			bb_update_option('i_api_user_display_name', '');
			bb_update_option('i_api_user_description', '');
        }
    }
    
	/**
	 * Returns whether the plugin is active or not
	 *
	 * @return boolean
	 * @author Sam Bauers
	 **/
	function isActive() {
		// if ($this->enabled && $this->active) {
		// 	return true;
		// } else {
		// 	return false;
		// }
		return true;
	}

    /*
     * Check if the current person is logged in.  If so,
     * return the corresponding BB_User.
     */
	function authenticate($username, $password) {
	  global $bbdb;
		if ( $this->api()->is_logged_in() ) {
			$username = $this->api()->user_info()->{bb_get_option('i_api_user_username')};
			$password = $this->_get_password();
		} else {
      $this->redirect_to_login();
		}
		$user = bb_get_user_by_name($username);

		if (! $user or $user->user_login != $username) {
			// User is logged into the API, but there's no 
			// bbPress user for them.  Are we allowed to 
			// create one?
			if ((bool) bb_get_option('i_api_auto_create_user')) {
			  $rails_id =  $this->api()->user_info()->{'id'};
			  $user_id =  $bbdb->get_var( $bbdb->prepare( "SELECT user_id FROM $bbdb->usermeta WHERE meta_key = 'rails_id' and meta_value = %d", $rails_id ) );
			  
			  if(!$user_id){
			    $this->_create_user($username);
  				$user = bb_get_user_by_name($username);
			  }else{
          $bbdb->update($bbdb->users, array( 'user_login' => $username, 'user_email' => $username ), array('ID' => $user_id ) );
          $user = bb_get_user($user_id);
			  }
				
			} else {
				// Bail out to avoid showing the login form
				bb_die("User $username does not exist in the our database and user auto-creation is disabled.");
			}
		}

		wp_set_auth_cookie($user->ID, $remember);
		do_action('bb_user_login', (int) $user->ID );
		return new WP_User($user->ID);
	}


	/**
	 * Disables standard registration
	 *
	 * @return void
	 * @author Sam Bauers
	 **/
	function disableRegistration()
	{
		if ($this->isActive() && $this->options['disable_registration'] && $this->locationIs('register.php')) {
			bb_die(__('Registration is disabled for this forum, please login using your LDAP username and password.'));
		}
	}


	/**
	 * Disables password recovery for users who have LDAP passwords
	 *
	 * @return void
	 * @author Sam Bauers
	 **/
	function disablePasswordRecovery()
	{
		if ($this->isActive() && $this->locationIs('bb-reset-password.php')) {
			$user_login = user_sanitize($_POST['user_login']);
			if (!empty($user_login)) {
				$user = bb_get_user_by_name($user_login);
				bb_die(__('Password recovery is not possible for this account because it uses an LDAP username and password to login. To change your LDAP password, please contact your system administrator.'));
			}
		}
	}


	/**
	 * Disables password editing for users who have LDAP passwords
	 *
	 * @return void
	 * @author Sam Bauers
	 **/
	function disablePasswordEditing()
	{
		global $bb_current_user;

		if ($this->isActive() && ($this->locationIs('profile.php') || $this->locationIs('profile-edit.php'))) {
			add_filter('bb_user_has_cap', array($this, 'removePasswordCapability'), 10, 2);
		}
	}
	

	/**
	 * Determines whether we are viewing the given page
	 *
	 * Mostly adapted from bb_get_location();
	 *
	 * @return boolean
	 * @author Sam Bauers
	 **/
	function locationIs($page)
	{
		$names = array(
			$_SERVER['PHP_SELF'],
			$_SERVER['SCRIPT_FILENAME'],
			$_SERVER['SCRIPT_NAME']
		);

		foreach ($names as $name) {
			if (false !== strpos($name, '.php')) {
				$file = $name;
			}
		}

		if (bb_find_filename($file) == $page) {
			return true;
		}
		return false;
	}


	/**
	 * Removes the change password capability for the current user
	 *
	 * @return array
	 * @author Sam Bauers
	 **/
	function removePasswordCapability($allcaps, $caps)
	{
		if ($caps[0] == 'change_password') {
			unset($allcaps['change_password']);
		}

		return $allcaps;
	}

	  
    /*
     * Send the user to the login page given by the API.
     */
    function redirect_to_login() {
        header('Location: ' . $this->api()->login_url());
        exit;
    }
    

    /*
     * Generate a password for the user. This plugin does not
     * require the user to enter this value, but we want to set it
     * to something nonobvious.
     */
    function generate_password($username, $password1, $password2) {
        $password1 = $password2 = $this->_get_password();
    }


    /*************************************************************
     * Private methods
     *************************************************************/
    
    
    /*
     * Generate a random password.
     */
    private function _get_password($length = 10) {
        return substr(md5(uniqid(microtime())), 0, $length);
    }


    /*
     * Create a new bbPress account for the specified username.
     */
    private function _create_user($username) {

        require_once(BB_PATH . BBINC . DIRECTORY_SEPARATOR . 'functions.bb-pluggable.php');
        
        $api_info = (array) $this->api()->user_info();

        $u = array();

        $u['user_pass']      = $this->_get_password();
        $u['user_login']     = $username;
        $u['user_email']     = $api_info[bb_get_option('i_api_user_email')];
        $u['user_url']       = $api_info[bb_get_option('i_api_user_website')];
        $u['user_firstname'] = $api_info[bb_get_option('i_api_user_firstname')];
        $u['user_lastname']  = $api_info[bb_get_option('i_api_user_lastname')];

        $u['nickname']       = $api_info[bb_get_option('i_api_user_nickname')];
        $u['display_name']   = $api_info[bb_get_option('i_api_user_display_name')];
        $u['description']    = $api_info[bb_get_option('i_api_user_description')];
 
    		$u['id'] = bb_new_user( $u['user_login'], $u['user_email'], $u['user_url']);
    		bb_update_user( $u['id'], $u['user_email'], $u['user_url'], $u['nickname'] );
    		bb_update_user_password( $u['id'], $u['user_pass'] );
    		bb_update_usermeta($u['id'], 'first_name', $u['user_firstname']);
    		bb_update_usermeta($u['id'], 'last_name', $u['user_firstname']);
    		bb_update_usermeta($u['id'], 'rails_id', $api_info['id']);
    }
}

// overriding default behavior to not send email
function bb_new_user( $user_login, $user_email, $user_url, $user_status = 1 ) {
	global $wp_users_object, $bbdb;

	// is_email check + dns
	if ( !$user_email = is_email( $user_email ) )
		return new WP_Error( 'user_email', __( 'Invalid email address' ), $user_email );

	if ( !$user_login = sanitize_user( $user_login, true ) )
		return new WP_Error( 'user_login', __( 'Invalid username' ), $user_login );

	// user_status = 1 means the user has not yet been verified
	$user_status = is_numeric($user_status) ? (int) $user_status : 1;
	if ( defined( 'BB_INSTALLING' ) )
		$user_status = 0;

	$user_nicename = $_user_nicename = bb_user_nicename_sanitize( $user_login );
	if ( strlen( $_user_nicename ) < 1 )
		return new WP_Error( 'user_login', __( 'Invalid username' ), $user_login );

	while ( is_numeric($user_nicename) || $existing_user = bb_get_user_by_nicename( $user_nicename ) )
		$user_nicename = bb_slug_increment($_user_nicename, $existing_user->user_nicename, 50);

	$user_url = $user_url ? bb_fix_link( $user_url ) : '';

	$user_pass = bb_generate_password();

	$user = $wp_users_object->new_user( compact( 'user_login', 'user_email', 'user_url', 'user_nicename', 'user_status', 'user_pass' ) );
	if ( is_wp_error($user) ) {
		if ( 'user_nicename' == $user->get_error_code() )
			return new WP_Error( 'user_login', $user->get_error_message() );
		return $user;
	}

	if (BB_INSTALLING) {
		bb_update_usermeta( $user['ID'], $bbdb->prefix . 'capabilities', array('keymaster' => true) );
	} else {
		bb_update_usermeta( $user['ID'], $bbdb->prefix . 'capabilities', array('member' => true) );
    // bb_send_pass( $user['ID'], $user['plain_pass'] );
	}

	do_action('bb_new_user', $user['ID'], $user['plain_pass']);
	return $user['ID'];
}
