<?php

/*
Plugin Name: One Click SSL
Plugin URI: https://tribulant.com/plugins/view/18/
Description: SSL redirect and automatic https:// resource conversion for your WordPress website.
Version: 1.6
Author: Tribulant Software
Author URI: https://tribulant.com
Text Domain: one-click-ssl
Domain Path: /languages
Network: true
*/

if (!defined('ABSPATH')) exit; // Exit if accessed directly

if (!defined('DS')) { define('DS', DIRECTORY_SEPARATOR); }

if (!class_exists('OCSSL')) {
	
	class OCSSL {
		
		var $plugin_data;
		var $plugin_path;
		var $plugin_url;
		var $plugin_base;
		var $plugin_name;
		var $plugin_version;

		public $ocssl_menu;
		
		// A list of http:// URLs found by build_url_list() method
		var $http_urls = array();
		
		function __construct() {
		
			require_once(ABSPATH . DS . 'wp-admin' . DS . 'includes' . DS . 'plugin.php');
			
			$this -> plugin_data = get_plugin_data(__FILE__);
			$this -> plugin_path = plugin_dir_path(__FILE__);
			$this -> plugin_url = plugin_dir_url(__FILE__);
			$this -> plugin_base = plugin_basename(__FILE__);
			$this -> plugin_name = dirname($this -> plugin_base);
			$this -> plugin_version = $this -> plugin_data['Version'];
		}
		
		function activation_hook() {
			
			// Add some default settings/options here
			add_option('ocssl', 0);
			add_option('ocssl_areas', "all");
			add_option('ocssl_activation_redirect', true);
			add_option('ocssl_nonsslredirect', 0);
			
			// Scheduled tasks
			$ratereview_scheduled = get_option('ocssl_ratereview_scheduled');
			if (empty($ratereview_scheduled)) {
				wp_schedule_single_event(strtotime("+7 day"), 'ocssl_ratereviewhook', array(7));
				wp_schedule_single_event(strtotime("+30 day"), 'ocssl_ratereviewhook', array(30));
				wp_schedule_single_event(strtotime("+60 day"), 'ocssl_ratereviewhook', array(60));
				update_option('ocssl_ratereview_scheduled', true);
			}
			
			return true;
		}
	
		function deactivation_hook() {
			update_option('ocssl', 0);
			update_option('ocssl_nonsslredirect', 0);
			
			// Dismissed messages
			update_option('ocssl_dismissed-ssloff', 0);
			update_option('ocssl_dismissed-ratereview', 0);
			
			return true;
		}
		
		function init_textdomain() {
			if (function_exists('load_plugin_textdomain')) {
				load_plugin_textdomain($this -> plugin_name, false, dirname(plugin_basename(__FILE__)) . DS . 'languages');
			}
		}
		
		function admin_head() {
			
		}
		
		function custom_redirect() {
			$activation_redirect = get_option('ocssl_activation_redirect');

			if (is_admin() && !empty($activation_redirect)) {
				delete_option('ocssl_activation_redirect');
				wp_cache_flush();
				
				$url = (is_multisite()) ? 
				network_admin_url('index.php?page=one-click-ssl-setup') :
				admin_url('index.php?page=one-click-ssl-setup');
				
				wp_redirect($url);
				exit();
			}
		}
		
		function admin_menu() {
		
			// If this is a multi-site network
			if (is_multisite() && is_network_admin()) {
				$this -> ocssl_menu = add_menu_page(__('One Click SSL', 'one-click-ssl'), __('One Click SSL', 'one-click-ssl'), 'manage_options', 'one-click-ssl', array($this, 'admin_network'), null, null);
			} else {
				$ocssl_toolsmenu = get_option('ocssl_toolsmenu');
				if (!empty($ocssl_toolsmenu)) {
					$this -> ocssl_menu = add_management_page(__('One Click SSL', 'one-click-ssl'), __('One Click SSL', 'one-click-ssl'), 'manage_options', 'one-click-ssl', array($this, 'admin'));
				} else {
					$this -> ocssl_menu = add_menu_page(__('One Click SSL', 'one-click-ssl'), __('One Click SSL', 'one-click-ssl'), 'manage_options', 'one-click-ssl', array($this, 'admin'), null, null);
				}
			}
			
			add_action('admin_head-' . $this -> ocssl_menu, array($this, 'admin_head_ocssl'));
			
			$this -> add_dashboard();
		}
		
		function admin_head_ocssl() {		
			if (is_multisite() && is_network_admin()) {
				add_meta_box('submitdiv', __('Save Settings', 'one-click-ssl'), array($this, "settings_submit"), $this -> ocssl_menu, 'side', 'core');
				add_meta_box('generaldiv', __('General Settings', 'one-click-ssl'), array($this, "settings_network_general"), $this -> ocssl_menu, 'normal', 'core');
			} else {			
				add_meta_box('submitdiv', __('Save Settings', 'one-click-ssl'), array($this, "settings_submit"), $this -> ocssl_menu, 'side', 'core');
				add_meta_box('generaldiv', __('General Settings', 'one-click-ssl'), array($this, "settings_general"), $this -> ocssl_menu, 'normal', 'core');
				add_meta_box('scannerdiv', __('Insecure Resources Scanner', 'one-click-ssl'), array($this, "settings_scanner"), $this -> ocssl_menu, 'normal', 'core');
			}
			
			// Normal boxes
			add_meta_box('statusdiv', __('SSL Status', 'one-click-ssl'), array($this, 'settings_status'), $this -> ocssl_menu, 'normal', 'core');
			
			// Side boxes
			add_meta_box('aboutdiv', __('About One Click SSL', 'one-click-ssl'), array($this, 'settings_about'), $this -> ocssl_menu, 'side', 'core');
			add_meta_box('pluginsdiv', __('Recommended Plugin', 'one-click-ssl'), array($this, 'settings_plugins'), $this -> ocssl_menu, 'side', 'core');
			
            if(!class_exists('Fusion_Custom_Icon_Set')) {
                do_action('do_meta_boxes', $this -> ocssl_menu, 'normal');
                do_action('do_meta_boxes', $this -> ocssl_menu, 'side');
            }
		}

		function add_dashboard() {
			add_dashboard_page(sprintf('One Click SSL %s', $this -> plugin_version), sprintf('One Click SSL %s', $this -> plugin_version), 'read', 'one-click-ssl-setup', array($this, 'admin_setup'));
			
			global $submenu;
			if (isset($submenu['index.php'])) {
				foreach ($submenu['index.php'] as $key => $value) {
					if (!empty($value[2]) && $value[2] === 'one-click-ssl-setup') {
						remove_submenu_page('index.php', 'one-click-ssl-setup');
						break;
					}
				}
			}
		}
		
		function settings_submit() {
			include($this -> plugin_path . 'views' . DS . 'settings-submit.php');
		}
		
		function settings_general() {
			include($this -> plugin_path . 'views' . DS . 'settings-general.php');
		}
		
		function settings_scanner() {
			include($this -> plugin_path . 'views' . DS . 'settings-scanner.php');
		}
		
		function settings_status() {
			include($this -> plugin_path . 'views' . DS . 'settings-status.php');
		}
		
		function settings_plugins() {
			include($this -> plugin_path . 'views' . DS . 'settings-plugins.php');
		}
		
		function settings_about() {
			include($this -> plugin_path . 'views' . DS . 'settings-about.php');
		}
		
		function settings_network_general() {
			include($this -> plugin_path . 'views' . DS . 'settings-network-general.php');
		}
		
		function admin() {		
			if (!current_user_can('manage_options')) {
				wp_die(__('You to not have permission', 'one-click-ssl'));
			}

										
			if (!empty($_POST)) {				

				check_admin_referer('ocssl-settings', 'security');

				update_option('ocssl', 0);
				update_option('ocssl_nonsslredirect', 0);
				update_option('ocssl_toolsmenu', 0);
				
				foreach ($_POST as $pkey => $pval) {
					update_option(sanitize_key($pkey), sanitize_text_field($pval));
				}
							
				
				wp_cache_flush();
				$this -> check_ssl();
				
				$this -> render_message(__('Settings have been saved', 'one-click-ssl'));
				do_action('ocssl_settings_saved', $_POST);
			}
			
			include($this -> plugin_path . 'views' . DS . 'settings.php');
		}
		
		function admin_network() {
			if (!empty($_POST)) {
				check_admin_referer('ocssl-settings', 'security');

				update_site_option('ocssl_global', 0);
				
				foreach ($_POST as $pkey => $pval) {
					update_site_option(sanitize_key($pkey), sanitize_text_field($pval));
				}
				
				wp_cache_flush();
				$this -> check_network_ssl();
				
				$this -> render_message(__('Settings have been saved', 'one-click-ssl'));
				do_action('ocssl_network_settings_saved', $_POST);
			}
			
			include($this -> plugin_path . 'views' . DS . 'settings-network.php');
		}
		
		function admin_setup() {
			if (!current_user_can('manage_options')) {
				wp_die(__('You do not have permission', 'one-click-ssl'));
			}

			delete_option('ocssl_activation_redirect');
			include($this -> plugin_path . 'views' . DS . 'setup.php');
		}
		
		function admin_enqueue_scripts() {
			$page = (!empty($_GET['page'])) ? sanitize_text_field($_GET['page']) : false;

			wp_enqueue_style('font-awesome', $this -> plugin_url . 'css/font-awesome.min.css', false, '4.7.0', "all");
			wp_enqueue_style('one-click-ssl', $this -> plugin_url . 'css/one-click-ssl.css', array('font-awesome'), $this -> plugin_version, "all");
			
			if (!empty($page) && ($page == 'one-click-ssl-setup' || $page == 'one-click-ssl')) {
				wp_enqueue_style('animate', $this -> plugin_url . 'css/animate.css', false, '1.0', "all");
				
				wp_enqueue_script('jquery');
				wp_enqueue_script('common');
				wp_enqueue_script('wp-lists');
				wp_enqueue_script('postbox');
				wp_enqueue_script('plugin-install');
				wp_enqueue_script('updates');
				
				add_thickbox();
				
				wp_enqueue_script('one-click-ssl-editor', $this -> plugin_url . 'js/one-click-ssl-editor.js', array('jquery'), $this -> plugin_version, true);
			}
			
			wp_register_script('one-click-ssl', $this -> plugin_url . 'js/one-click-ssl.js', array('jquery'), $this -> plugin_version, true);
				
			$translation_array = array(
				'is_ssl'					=>	is_ssl(),
				'settings_url'				=>	((is_multisite()) ? network_admin_url('admin.php?page=one-click-ssl') : admin_url('admin.php?page=one-click-ssl')),
				'settingswarning' 			=> 	__('By turning on SSL, your server/hosting must support SSL (https://) or this could make your website inaccessible.' . "\r\n\r\n" . 'Upon clicking OK, you will be asked to log in to your WordPress dashboard again if the protocol changes.' . "\r\n\r\n" . 'If you are uncertain, click Cancel below.', 'one-click-ssl'),
				'ajaxnonce'					=>	array(
					'check_ssl_support'			=>	wp_create_nonce('check_ssl_support'),
					'enable_ssl'				=>	wp_create_nonce('enable_ssl'),
					'scan'						=>	wp_create_nonce('scan'),
					'dismissed_notice'			=>	wp_create_nonce('dismissed_notice'),
				),
			);
			
			wp_localize_script('one-click-ssl', 'ocssl', $translation_array);
			wp_enqueue_script('one-click-ssl');
		}
		
		function ratereview_hook($days = 30) {
			
			update_option('ocssl_showmessage_ratereview', $days);
			delete_option('ocssl_hidemessage_ratereview');
			delete_option('ocssl_dismissed-ratereview');

			return true;
		}
		
		function admin_notices() {
			
			// Check if SSL is not running
			if (!is_ssl()) {
				$message = sprintf(__('SSL not enabled, you are on an insecure connection. %s', 'one-click-ssl'), '<a class="button button-primary" href="' . admin_url('index.php?page=one-click-ssl-setup') . '"><i class="fa fa-shield fa-fw"></i> ' . __('Enable SSL', 'one-click-ssl') . '</a>');
				$this -> render_message($message, 'error', true, 'ssloff');
			}
			
			// Rate & Review

            if ( get_option( 'one_click_ssl_smart_rating_dismissed', false ) ) {
                return;
            }

            $nonce = wp_create_nonce( 'one_click_ssl_feedback_notification_bar_nonce' );

			$showmessage_ratereview = get_option('ocssl_showmessage_ratereview');
			if (!empty($showmessage_ratereview)) {
				$rate_url = "https://wordpress.org/support/plugin/one-click-ssl/reviews/?rate=5#new-post";
				$message = sprintf(__('You have been using %s for some time. Please consider to %s on %s. We appreciate it very much! %s', 'one-click-ssl'), '<a href="https://wordpress.org/support/plugin/one-click-ssl/" target="_blank">' . __('One Click SSL', 'one-click-ssl') . '</a>', '<a href="' . $rate_url . '" target="_blank" class="button"><i class="fa fa-star"></i> ' . __('leave your rating', 'one-click-ssl') . '</a>', '<a href="https://wordpress.org/support/plugin/one-click-ssl/reviews/" target="_blank">WordPress.org</a>', '<button type="button" class="button my-custom-dismiss-button" data-nonce="' . $nonce .'">' . __('Dismiss forever', 'one-click-ssl') . '</button>');
				$message .= "
								<script>
								jQuery('.my-custom-dismiss-button').on('click', function(e) {
									e.preventDefault();
                                var nonce =jQuery(this).attr('data-nonce');
                                jQuery.post(ajaxurl,{action:'one_click_ssl_dismiss_smart_rating',nonce:nonce})
								  jQuery('.notice-one-click-ssl .notice-dismiss').trigger('click');
								});
								</script>";
				$this -> render_message($message, 'success', true, 'ratereview');
			}
		}
		
        public function dismiss_smart_rating() {
            $nonce = isset($_POST['nonce']) ? $_POST['nonce'] : '';
            $action = 'one_click_ssl_feedback_notification_bar_nonce';
            if (!wp_verify_nonce($nonce, $action)) {
                wp_send_json_error();
            }

            if ( false === get_option( 'one_click_ssl_smart_rating_dismissed' ) && false === update_option( 'one_click_ssl_smart_rating_dismissed', false ) ) {
                add_option( 'one_click_ssl_smart_rating_dismissed', true );
            }
            wp_send_json_success();
        }


		function plugin_action_links($actions = null, $plugin_file = null, $plugin_data = null, $context = null) {
			if (!empty($plugin_file) && $plugin_file == $this -> plugin_base) {
				if (is_multisite() && is_network_admin()) {
					$actions[] = '<a href="' . network_admin_url('admin.php?page=one-click-ssl') . '">' . __('Settings', 'one-click-ssl') . '</a>';
					$actions = apply_filters('ocssl_plugin_actions', $actions);
				} else {
					$actions[] = '<a href="' . admin_url('admin.php?page=one-click-ssl') . '">' . __('Settings', 'one-click-ssl') . '</a>';
					$actions = apply_filters('ocssl_plugin_actions', $actions);
				}
			}
			
			return $actions;
		}
		
		function render_message($message = null, $type = 'success', $dismissible = true, $slug = null) {			
			if (!empty($dismissible) && !empty($slug)) {
				$dismissed = get_option('ocssl_dismissed-' . $slug);
				if (!empty($dismissed)) {
					return;
				}
			}
			
			if (!empty($message)) {
				?>
				
				<div id="<?php echo $type; ?>" class="notice notice-<?php echo $type; ?> notice-one-click-ssl <?php echo (!empty($dismissible)) ? 'is-dismissible' : ''; ?>" data-notice="<?php echo esc_attr($slug); ?>">
			        <p>
				        <?php
					        
					        
					    switch ($type) {
						    case 'error'			:
						    	echo '<i class="fa fa-times fa-fw"></i>';
						    	break;
						    case 'warning'			:
						    	echo '<i class="fa fa-exclamation-triangle fa-fw"></i>';
						    	break;
						    case 'success'			:
						    default 				:
						    	echo '<i class="fa fa-check fa-fw"></i>';
						    	break;
					    }    
				        
				        ?>
				        <?php echo $message; ?>
				    </p>
			    </div>
				
				<?php
			}
		}
		
		function make_request($url = null) {
			global $ocssl_http_code;
			
			if (empty($url)) {
				$url = home_url(false, 'https');	
			}
			
			$timeout = 5;
			$body = false;

				$args = array(
					'timeout'     	=> 	$timeout,
					'httpversion' 	=> 	'1.1',
					'sslverify'   	=> 	true,
					'body'			=>	array('ocssl_check' => true),
				);
				
				$response = wp_remote_post($url, $args);
				
				if (!is_wp_error($response)) {
					$ocssl_http_code = $response['response']['code'];
					if (!empty($response['response']['code']) && $response['response']['code'] == 200) {
						$body = $response['body'];
					}
				}
			
			$response = array(
				'code'			=>	$ocssl_http_code,
				'body'			=>	$body,
			);
			
			return $response;
		}
		
		function gen_date($format = "Y-m-d H:i:s", $time = false, $gmt = false, $includetime = false) {
			if (empty($format)) {
				$format = get_option('date_format'); 
				
				if (!empty($includetime)) {
					$format .= ' ' . get_option('time_format');
				}
			} 
			
			$newtime = (empty($time)) ? false : $time;
			return date_i18n($format, $newtime, $gmt);
		}
		
		function get_certificate_info() {
			$certinfo = false;
			
			$url = home_url(null, 'https');
			$orignal_parse = parse_url($url, PHP_URL_HOST);
			
			try {
				$get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
				$read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
				$cert = stream_context_get_params($read);
				$certificate = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
				
				$certinfo = array(
					'isvalid'			=>	true,
					'issuer'			=>	$certificate['issuer']['CN'],
					'domain'			=>	$certificate['subject']['CN'],
					'expiry'			=>	$this -> gen_date(false, $certificate['validTo_time_t']),
				);
			} catch (Exception $e) {
				$certinfo = array(
					'isvalid'			=>	false,
					'domain'			=>	$hostname,
					'message'			=>	$e -> getMessage(),
				);
			}
			
			return $certinfo;
		}
		
		function has_ssl_support() {	
			global $ocssl_http_code;
					
			$has_ssl = false;
			$url = home_url(false, 'https');
			
			if ($response = $this -> make_request($url)) {
				if (!empty($response['code']) && $response['code'] == 200) {
					$has_ssl = true;
				}	
			}
	
			return apply_filters('ocssl_has_ssl', $has_ssl);
		}
		
		function check_ssl() {			
			
			// Don't do redirects if the SSL support is being checked
			if (!empty($_POST['ocssl_check'])) {
				return;
			}
											
			// Is SSL turned on ?
			$ocssl = get_option('ocssl');
			
			$ocssl_nonsslredirect = get_option('ocssl_nonsslredirect');	
			$nonssl = (!empty($ocssl_nonsslredirect)) ? true : false;
				
			if (!empty($ocssl)) {
				$ocssl_areas = get_option('ocssl_areas');
				$doredirect = false;
				$redirecturl = "https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
				
				switch ($ocssl_areas) {
					case 'admin'				:
						// Only redirect the admin dashboard
						if ((is_admin() && !defined('DOING_AJAX')) || $GLOBALS['pagenow'] === 'wp-login.php') {
							$doredirect = true;
							$nonssl = false;
						}
						break;
					case 'front'				:
						// Only redirect when it's not the admin dashboard
						if (!is_admin() && $GLOBALS['pagenow'] !== 'wp-login.php') {							
							$doredirect = true;
							$nonssl = false;
						}
						break;
					case 'all'					:
					default 					:
						// Redirect everything, all pages and sections
						$doredirect = true;
						$nonssl = false;
						break;
				}
				
				if (!empty($doredirect)) {
					if (!is_ssl()) {
						// Go ahead and do the redirect
						$this -> redirect($redirecturl);
					}
				}	
			}
			
			// Redirect to non-SSL if we are on https:// but SSL setting is turned off
			if (!empty($nonssl) && $nonssl == true) {			
				if (is_ssl()) {					
					$redirecturl = "http://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
					$this -> redirect($redirecturl);
				}
			}
		}
		
		function check_network_ssl() {											
			// Is SSL turned on ?
			$ocssl_global = get_site_option('ocssl_global');
				
			if (!empty($ocssl_global)) {
				$redirecturl = "https://" . $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
				
				if (!is_ssl()) {
					// Go ahead and do the redirect
					$this -> redirect($redirecturl);
				}
			}
		}
		
		function redirect($redirecturl = null) {
			if (!empty($redirecturl)) {
				if (headers_sent()) {					
					?>
						
					<script type="text/javascript">
					document.location = "<?php echo esc_attr(stripslashes($redirecturl)); ?>";
					</script>
					
					<?php
				} else {
					wp_redirect($redirecturl, "301");
					exit();
				}
			}
		}
	
		function replace_https($value = null) {	
			if (!empty($value)) {
				$ocssl = get_option('ocssl');
				if (!empty($ocssl)) {	
					if (is_ssl()) {
						if (!is_array($value) && !is_object($value)) {
							$value = preg_replace('|/+$|', '', $value);
							$value = preg_replace('|http://|', 'https://', $value);
						}		
					}
				}
			}
		
			return apply_filters('ocssl_replace_https', $value);
		}
		
		function ajax_check_ssl_support() {

			check_ajax_referer('check_ssl_support', 'security');

			if (!current_user_can('manage_options')) {
				wp_die(__('You do not have permission', 'one-click-ssl'));
			}
			
			ob_start();
			
			global $ocssl_http_code;
			
			if ($this -> has_ssl_support()) {
				$response = array('success' => true, 'http_code' => $ocssl_http_code);
			} else {
				$error = sprintf('<i class="fa fa-times"></i> ' . __('SSL is not supported. Website returned response code %s over SSL. Please ask your hosting provider to check for you.', 'one-click-ssl'), '<strong>' . $ocssl_http_code . '</strong>');
				$response = array('success' => false, 'http_code' => $ocssl_http_code, 'error' => $error);
			}
			
			$process = ob_get_clean();
			echo json_encode($response);
			
			exit();
			die();
		}
		
		function ajax_enable_ssl() {
			check_ajax_referer('enable_ssl', 'security');

			if (!current_user_can('manage_options')) {
				wp_die(__('You do not have permission', 'one-click-ssl'));
			}
			
			if (is_multisite()) {
				update_site_option('ocssl_global', 1);	
			} else {
				update_option('ocssl', 1);
			}
				
			wp_cache_flush();
			
			exit();
			die();
		}
		
		function ajax_scan() {
			check_ajax_referer('scan', 'security');

			if (!current_user_can('manage_options')) {
				wp_die(__('You do not have permission', 'one-click-ssl'));
			}
			
			ob_start();
			
			$success = false;
			$insecure = false;
			
			$url = home_url('/', 'https');
			if (!empty($_POST['scanurl'])) {
				$scanurl = sanitize_url($_POST['scanurl']);
				$url .= ltrim($scanurl, '/');
			}
			
			$output = '';
			
			if ($response = $this -> make_request($url)) {				
				if (!empty($response) && $response['code'] == 200) {					
					$pattern = '/<[script|link|base|img|form][^>]*[href|src|action]=[\'"]\K(http:\/\/[^\'"]+)[\'"]/i';
					preg_match_all($pattern, $response['body'], $matches);
					
					if (!empty($matches[1])) {
						$success = false;
						$insecure = $matches[1];
						
						$output .= '<div class="alert alert-warning">';
						$output .= '<i class="fa fa-exclamation-triangle fa-fw"></i> ' . sprintf(__('%s Insecure resources found on the URL, make them https:// for SSL to validate', 'one-click-ssl'), count($matches[1]));
						
						$output .= '<ul>';
						foreach ($matches[1] as $insecure_url) {
							$output .= '<li>' . $insecure_url . '</li>';
						}
						$output .= '</ul>';
						
						$output .= '</div>';
					} else {
						$success = true;
						$insecure = false;
						
						$output .= '<div class="alert alert-success">';
						$output .= '<i class="fa fa-check fa-fw"></i> ' . __('No insecure resources found, SSL will validate!', 'one-click-ssl');
						$output .= '</div>';
					}
				} else {
					$success = false;
					$insecure = false;
					$output .= '<div class="alert alert-danger"><i class="fa fa-times fa-fw"></i> ' . sprintf(__('URL could not be loaded - Code %s', 'one-click-ssl'), $response['code']) . '</div>';
				}
			} else {
				$success = false;
				$insecure = false;
				$output .= '<div class="alert alert-danger"><i class="fa fa-times fa-fw"></i> ' . __('Request failed, please try again.', 'one-click-ssl') . '</div>';
			}
			
			$reply = array(
				'success'			=>	$success,
				'insecure'			=>	$insecure,
				'output'			=>	$output
			);
			
			$process = ob_get_clean();
			echo json_encode($reply);
			
			exit();
			die();
		}
		
		function ajax_dismissed_notice() {
			check_ajax_referer('dismissed_notice', 'security');

			if (!current_user_can('manage_options')) {
				wp_die(__('You do not have permission', 'one-click-ssl'));
			}
			
			// Pick up the notice "slug" - passed via jQuery (the "data-notice" attribute on the notice)
		    $slug = sanitize_text_field($_REQUEST['slug']);
		    // Store it in the options table
		    update_option('ocssl_dismissed-' . $slug, true);
		    
		    exit();
		    die();
		}
		
		function is_plugin_active($name = null, $orinactive = false) {
			if (!empty($name)) {
				require_once ABSPATH . 'wp-admin' . DS . 'includes' . DS . 'admin.php';

				$path = $name;
				$path2 = str_replace("\\", "/", $path);
	
				if (!empty($path)) {
					$plugins = get_plugins();
	
					if (!empty($plugins)) {
						if (array_key_exists($path, $plugins) || array_key_exists($path2, $plugins)) {
							/* Let's see if the plugin is installed and activated */
							if (is_plugin_active(plugin_basename($path)) ||
								is_plugin_active(plugin_basename($path2))) {
								return true;
							}
	
							/* Maybe the plugin is installed but just not activated? */
							if (!empty($orinactive) && $orinactive == true) {
								if (is_plugin_inactive(plugin_basename($path)) ||
									is_plugin_inactive(plugin_basename($path2))) {
									return true;
								}
							}
						}
					}
				}
			}
	
			return false;
		}
		
		function filter_buffer($buffer = null) {
			$buffer = $this -> replace_insecure_links($buffer);
			return $buffer;
		}
		
		function start_buffer() {
			// Check if SSL is enabled and current protocol is SSL
			$ocssl = get_option('ocssl');
			if (!empty($ocssl) && is_ssl()) {
				$this -> build_url_list();
				ob_start(array($this, "filter_buffer"));
			}
		}
		
		function stop_buffer() {
			// Check if SSL is enabled and current protocol is SSL
			$ocssl = get_option('ocssl');
			if (!empty($ocssl) && is_ssl()) {
				if (ob_get_length()) {
					ob_end_flush();
				}
			}
		}
		
		function build_url_list() {
			$home = str_replace("https://", "http://" , get_option('home'));
			$home_no_www  = str_replace("://www.", "://", $home);
			$home_yes_www = str_replace("://", "://www.", $home_no_www);
			$escaped_home = str_replace("/", "\/", $home);
			
			$this -> http_urls = array(
				$home_yes_www,
				$home_no_www,
				$escaped_home,
				"src='http://",
				'src="http://',
			);
		}
		
		function replace_insecure_links($str = null) {			
			$search_array = apply_filters('ocssl_replace_search_list', $this -> http_urls);
			$ssl_array = str_replace(array("http://", "http:\/\/"), array("https://", "https:\/\/"), $search_array);
			$str = str_replace($search_array, $ssl_array, $str);
			
			$patterns = array(
				'/url\([\'"]?\K(http:\/\/)(?=[^)]+)/i',
				'/<link .*?href=[\'"]\K(http:\/\/)(?=[^\'"]+)/i',
				'/<meta property="og:image" .*?content=[\'"]\K(http:\/\/)(?=[^\'"]+)/i',
				'/<form [^>]*?action=[\'"]\K(http:\/\/)(?=[^\'"]+)/i',
				'/<(script|svg|link|base|img|form)[^>]*(xmlns|href|src|action)=[\'"]\K(http:\/\/)(?=[^\'"]+)/i',
			);
			
			$str = preg_replace($patterns, 'https://', $str);
			
			global $ocssl_bodydata;
			if (empty($ocssl_bodydata)) {
				$str = str_replace("<body ", "<body data-ocssl='1' ", $str);
				$ocssl_bodydata = true;
			}
			
			return apply_filters("ocssl_replace_output", $str);
		}
		
		function debug($var = array()) {
			echo '<pre>' . print_r($var, true) . '</pre>';
		}


        function save_check_settings() {
            // Only run in the admin area
            if (!is_admin() || empty($_POST)) {
                return;
            }

            // Verify the nonce for security
            if (!check_admin_referer('ocssl-settings', 'security')) {
                wp_die(__('Security check failed', 'one-click-ssl'));
            }

            update_option('ocssl', 0);
            update_option('ocssl_nonsslredirect', 0);
            update_option('ocssl_toolsmenu', 0);

            foreach ($_POST as $pkey => $pval) {
                update_option(sanitize_key($pkey), sanitize_text_field($pval));
            }

            $ocssl_toolsmenu = !empty($_POST['ocssl_toolsmenu']) ? $_POST['ocssl_toolsmenu'] : 0;

            if (!empty($ocssl_toolsmenu)) {
                update_option('ocssl_toolsmenu', 1);
                if (!wp_doing_ajax()) {
                    wp_redirect(admin_url('tools.php?page=one-click-ssl'));
                    exit();
                }
            }

            if (empty($ocssl_toolsmenu)) {
                update_option('ocssl_toolsmenu', 0);
                if (!wp_doing_ajax()) {
                    wp_redirect(admin_url('admin.php?page=one-click-ssl'));
                    exit();
                }
            }

            wp_cache_flush();
            $this->check_ssl();
            $this->render_message(__('Settings have been saved', 'one-click-ssl'));
            do_action('ocssl_settings_saved', $_POST);

            include($this->plugin_path . 'views' . DS . 'settings.php');
        }
    }


	
	if (!function_exists('OCSSL')) {
		function OCSSL($params = null) {
			return new OCSSL($params);
		}
	}
	
	$ocssl = new OCSSL();
	
	register_activation_hook(__FILE__, array($ocssl, 'activation_hook'));
	register_deactivation_hook(__FILE__, array($ocssl, 'deactivation_hook'));
	
	add_action('admin_init', array($ocssl, 'start_buffer'), 10, 1);
	add_action('init', array($ocssl, 'start_buffer'), 10, 1);
	add_action('shutdown', array($ocssl, 'stop_buffer'), 10, 1);
	add_action('ocssl_ratereviewhook', array($ocssl, 'ratereview_hook'), 10, 1);
	add_action('init', array($ocssl, 'init_textdomain'), 10, 1);
	add_action('admin_init', array($ocssl, 'custom_redirect'), 10, 1);
	add_action('admin_head', array($ocssl, 'admin_head'), 10, 1);
	
	if (is_multisite()) {
		add_action('network_admin_menu', array($ocssl, 'admin_menu'), 10, 1);
	} else {
		add_action('admin_menu', array($ocssl, 'admin_menu'), 10, 1);
	}
		
	add_action('admin_enqueue_scripts', array($ocssl, 'admin_enqueue_scripts'), 10, 1);
	add_action('admin_notices', array($ocssl, 'admin_notices'), 10, 1);
    add_action( 'wp_ajax_one_click_ssl_dismiss_smart_rating', array( $ocssl, 'dismiss_smart_rating' ) );

	if (is_multisite()) {
		add_action('wp_loaded', array($ocssl, 'check_network_ssl'), 10, 1);	
	} else {
		add_action('wp_loaded', array($ocssl, 'check_ssl'), 10, 1);
	}
	
	if (is_multisite()) {
		add_filter('network_admin_plugin_action_links', array($ocssl, 'plugin_action_links'), 10, 4);
	} else {
		add_filter('plugin_action_links', array($ocssl, 'plugin_action_links'), 10, 4);
	}
	
	add_filter('upload_dir', array($ocssl, 'replace_https'));
	add_filter('option_siteurl', array($ocssl, 'replace_https'));
	add_filter('option_home', array($ocssl, 'replace_https'));
	add_filter('option_url', array($ocssl, 'replace_https'));
	add_filter('option_wpurl', array($ocssl, 'replace_https'));
	add_filter('option_stylesheet_url', array($ocssl, 'replace_https'));
	add_filter('option_template_url', array($ocssl, 'replace_https'));
	add_filter('wp_get_attachment_url', array($ocssl, 'replace_https'));
	add_filter('widget_text', array($ocssl, 'replace_https'));
	add_filter('login_url', array($ocssl, 'replace_https'));
	add_filter('language_attributes', array($ocssl, 'replace_https'));
	
	// Ajax Actions
	add_action('wp_ajax_ocssl_check_ssl_support', array($ocssl, 'ajax_check_ssl_support'));
	add_action('wp_ajax_ocssl_enable_ssl', array($ocssl, 'ajax_enable_ssl'));
	add_action('wp_ajax_ocssl_scan', array($ocssl, 'ajax_scan'));
	add_action('wp_ajax_ocssl_dismissed_notice', array($ocssl, 'ajax_dismissed_notice'));


    // Hook into admin_init and check the page
    add_action('admin_init', function() use ($ocssl) {
        $current_page = isset($_GET['page']) ? $_GET['page'] : '';
        if ($current_page === 'one-click-ssl' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $ocssl->save_check_settings();
        }
    });
}
