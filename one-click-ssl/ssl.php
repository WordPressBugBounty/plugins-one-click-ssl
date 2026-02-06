<?php

/*
Plugin Name: One Click SSL
Plugin URI: https://tribulant.com/plugins/view/18/
Description: SSL/TLS redirect and automatic https:// resource conversion for your WordPress website.
Version: 1.7.5
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
			 add_action('init', array($this, 'register_ssl_check_endpoint'));
		}
		

		
// Update the register_ssl_check_endpoint method
function register_ssl_check_endpoint() {
    // Register the rewrite rule
    add_rewrite_rule(
        '^ocssl-check$',
        'index.php?ocssl_check=1',
        'top'
    );

    // Add the query var
    add_filter('query_vars', function($vars) {
        $vars[] = 'ocssl_check';
        return $vars;
    });

    // Handle the endpoint request
    add_action('template_redirect', function() {
        if (get_query_var('ocssl_check')) {
            // Set headers for JSON response
            header('Content-Type: application/json');
            header('Cache-Control: no-cache');

            // Return a simple JSON response
            $response = array(
                'success' => true,
                'message' => 'SSL check endpoint reached.',
            );

            // Output the response and exit
            wp_send_json($response);
            exit;
        }
    });
}

		
		
		public function load_plugin_data() {
	        $this->plugin_data = get_plugin_data(__FILE__);
	        $this->plugin_path = plugin_dir_path(__FILE__);
	        $this->plugin_url = plugin_dir_url(__FILE__);
	        $this->plugin_base = plugin_basename(__FILE__);
	        $this->plugin_name = dirname($this->plugin_base);
	        $this->plugin_version = $this->plugin_data['Version'];
	    }

		function activation_hook() {
			
		    $this->register_ssl_check_endpoint();
		    flush_rewrite_rules();

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
			

		    // Flush rewrite rules to remove the custom endpoint
		    flush_rewrite_rules();

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

		    // Determine where the “One Click SSL” item should go
		    if ( is_multisite() && is_network_admin() ) {
		        // in network admin we save it as a site‐option
		        $ocssl_toolsmenu = get_site_option( 'ocssl_toolsmenu' );
		    } else {
		        // on single‐site (or in sub‐site admin) we use the regular option
		        $ocssl_toolsmenu = get_option( 'ocssl_toolsmenu' );
		    }

		    // If this is a multi‐site network
		    if ( is_multisite() && is_network_admin() ) {
		        if ( ! empty( $ocssl_toolsmenu ) ) {
		            // under Settings
		            $this->ocssl_menu = add_submenu_page(
		                'settings.php',
		                __( 'One Click SSL', 'one-click-ssl' ),
		                __( 'One Click SSL', 'one-click-ssl' ),
		                'manage_options',
		                'one-click-ssl',
		                [ $this, 'admin_network' ]
		            );
		        } else {
		            // top‐level menu
		            $this->ocssl_menu = add_menu_page(
		                __( 'One Click SSL', 'one-click-ssl' ),
		                __( 'One Click SSL', 'one-click-ssl' ),
		                'manage_options',
		                'one-click-ssl',
		                [ $this, 'admin_network' ]
		            );
		        }
		    } else {
		        // single-site or sub-site admin
		        if ( ! empty( $ocssl_toolsmenu ) ) {
		            // under Tools
		            $this->ocssl_menu = add_management_page(
		                __( 'One Click SSL', 'one-click-ssl' ),
		                __( 'One Click SSL', 'one-click-ssl' ),
		                'manage_options',
		                'one-click-ssl',
		                [ $this, 'admin' ]
		            );
		        } else {
		            // top-level
		            $this->ocssl_menu = add_menu_page(
		                __( 'One Click SSL', 'one-click-ssl' ),
		                __( 'One Click SSL', 'one-click-ssl' ),
		                'manage_options',
		                'one-click-ssl',
		                [ $this, 'admin' ]
		            );
		        }
		    }

		    add_action( 'admin_head-' . $this->ocssl_menu, [ $this, 'admin_head_ocssl' ] );
		    $this->add_dashboard();
		}

		
		function admin_head_ocssl() {		
			if (is_multisite() && is_network_admin()) {
				add_meta_box('submitdiv', __('Save Settings', 'one-click-ssl'), array($this, "settings_submit"), $this -> ocssl_menu, 'side', 'core');
				add_meta_box('generaldiv', __('General Settings', 'one-click-ssl'), array($this, "settings_network_general"), $this -> ocssl_menu, 'normal', 'core');
			} else {			
				add_meta_box('submitdiv', __('Save Settings', 'one-click-ssl'), array($this, "settings_submit"), $this -> ocssl_menu, 'side', 'core');
				add_meta_box('generaldiv', __('General Settings', 'one-click-ssl'), array($this, "settings_general"), $this -> ocssl_menu, 'normal', 'core');
			}
			
			add_meta_box('scannerdiv', __('Insecure Resources Scanner', 'one-click-ssl'), array($this, "settings_scanner"), $this -> ocssl_menu, 'normal', 'core');

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
		}

		function remove_dashboard() 
		{
			?>
			<style>
				/* Hide the menu item linking to banners-about */
				#adminmenu a[href="index.php?page=one-click-ssl-setup"] {
					display: none !important;
				}
			</style>
			<?php
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
		
		public function admin_network() {
		    // Log request details
		    error_log('OCSSL admin_network: REQUEST_METHOD=' . $_SERVER['REQUEST_METHOD']);
		    error_log('OCSSL admin_network: REQUEST_URI=' . $_SERVER['REQUEST_URI']);
		    error_log('OCSSL admin_network: POST=' . print_r($_POST, true));

		    // Check if this is a form submission (POST request)
		    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		        // Verify nonce
		        if (!check_admin_referer('ocssl-settings', 'security')) {
		            error_log('OCSSL admin_network: Nonce verification failed');
		            wp_die(__('Security check failed', 'one-click-ssl'));
		        }

		        // Log form submission
		        if (isset($_POST['ocssl_form_submitted'])) {
		            error_log('OCSSL admin_network: Form submitted with ocssl_form_submitted');
		        }

		        // Get current ocssl_global value
		        $current_ocssl_global = get_site_option('ocssl_global');
		        error_log('OCSSL admin_network: Current ocssl_global=' . $current_ocssl_global);

		        // Set ocssl_global based on POST data
		        $new_ocssl_global = isset($_POST['ocssl_global']) ? 1 : 0;
		        update_site_option('ocssl_global', $new_ocssl_global);
		        error_log('OCSSL admin_network: Saving ocssl_global=' . $new_ocssl_global);

		        // Handle other fields
		        $post_fields = ['ocssl_areas', 'ocssl_toolsmenu', 'ocssl_auth_username', 'ocssl_auth_password', 'ocssl_nonsslredirect'];
		        foreach ($post_fields as $pkey) {
		            if (isset($_POST[$pkey])) {
		                if ($pkey === 'ocssl_auth_password') {
		                    update_site_option(sanitize_key($pkey), $_POST[$pkey]);
		                } else {
		                    update_site_option(sanitize_key($pkey), sanitize_text_field($_POST[$pkey]));
		                }
		            } else {
		                update_site_option(sanitize_key($pkey), '');
		            }
		        }

		        // Flush cache
		        wp_cache_flush();
		        error_log('OCSSL admin_network: Cache flushed');

		        // Run network SSL check
		        $this->check_network_ssl();
		        $updated_ocssl_global = get_site_option('ocssl_global');
		        error_log('OCSSL admin_network: After check_network_ssl ocssl_global=' . $updated_ocssl_global);

		        // Queue settings saved notice
		        set_transient('ocssl_settings_notice', [
		            'message' => __('Settings have been saved', 'one-click-ssl'),
		            'type' => 'success',
		            'dismissible' => true,
		            'slug' => 'settings-saved'
		        ], 30);
		        
		        do_action('ocssl_network_settings_saved', $_POST);

		        // Redirect to prevent form resubmission
		        wp_redirect(network_admin_url('admin.php?page=one-click-ssl'));
		        exit;
		    }

		    include($this->plugin_path . 'views' . DS . 'settings-network.php');
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

			wp_localize_script('one-click-ssl', 'ocssl', [
			    'ajaxnonce' => [
			        'scan' => wp_create_nonce('scan'),
			        'dismiss' => wp_create_nonce('ocssl_dismiss_notice')
			    ]
			]);
			
			wp_register_script('one-click-ssl', $this -> plugin_url . 'js/one-click-ssl.js', array('jquery'), $this -> plugin_version, true);
				
			$translation_array = array(
				'is_ssl'					=>	is_ssl(),
				'settings_url'				=>	((is_multisite()) ? network_admin_url('admin.php?page=one-click-ssl') : admin_url('admin.php?page=one-click-ssl')),
				'settingswarning' 			=> 	__('By turning on SSL, your server/hosting must support SSL (https://) or this could make your website inaccessible.' . "\r\n\r\n" . 'Upon clicking OK, you will be asked to log in to your WordPress dashboard again if the protocol changes.' . "\r\n\r\n" . 'If you are uncertain, click Cancel below.', 'one-click-ssl'),
				'ajaxnonce'					=>	array(
					'check_ssl_support'	=>	wp_create_nonce('check_ssl_support'),
					'enable_ssl'        =>	wp_create_nonce('enable_ssl'),
					'scan'              =>	wp_create_nonce('scan'),
					'dismissed_notice'  =>	wp_create_nonce('dismissed_notice'),
					'dismiss'           =>	wp_create_nonce('ocssl_dismiss_notice'),
				),
				// Add translations for auth form
				'username_label' => __('Username:', 'one-click-ssl'),
				'password_label' => __('Password:', 'one-click-ssl'),
				'retry_button' => __('Retry with Credentials', 'one-click-ssl'),
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
		
		public function admin_notices() {
		    if (WP_DEBUG) {
		        error_log('OCSSL admin_notices: Checking notices');
		    }

		    if (!is_ssl()) {
		        $message = sprintf(__('SSL not enabled, you are on an insecure connection. % мальшеs', 'one-click-ssl'), '<a class="button button-primary" href="' . admin_url('index.php?page=one-click-ssl-setup') . '"><i class="fa fa-shield fa-fw"></i> ' . __('Enable SSL', 'one-click-ssl') . '</a>');
		        echo $this->render_message($message, 'error', true, 'ssloff');
		    }
		    
		    if (!get_option('one_click_ssl_smart_rating_dismissed', false)) {
		        $nonce = wp_create_nonce('ocssl_dismiss_notice');
		        $showmessage_ratereview = get_option('ocssl_showmessage_ratereview');
		        if (!empty($showmessage_ratereview)) {
		            $rate_url = "https://wordpress.org/support/plugin/one-click-ssl/reviews/?rate=5#new-post";
		            $message = sprintf(__('You have been using %s for some time. Please consider to %s on %s. We appreciate it very much! %s', 'one-click-ssl'), '<a href="https://wordpress.org/support/plugin/one-click-ssl/" target="_blank">' . __('One Click SSL', 'one-click-ssl') . '</a>', '<a href="' . $rate_url . '" target="_blank" class="button"><i class="fa fa-star"></i> ' . __('leave your rating', 'one-click-ssl') . '</a>', '<a href="https://wordpress.org/support/plugin/one-click-ssl/reviews/" target="_blank">WordPress.org</a>', '<button type="button" class="button my-custom-dismiss-button" data-nonce="' . $nonce .'" data-slug="ratereview">' . __('Dismiss forever', 'one-click-ssl') . '</button>');
		            echo $this->render_message($message, 'success', true, 'ratereview');
		        }
		    }
		    
		    $settings_notice = get_transient('ocssl_settings_notice');
		    if (WP_DEBUG) {
		        error_log('OCSSL admin_notices: settings_notice=' . print_r($settings_notice, true));
		    }
		    if ($settings_notice && is_array($settings_notice)) {
		        echo $this->render_message($settings_notice['message'], $settings_notice['type'], $settings_notice['dismissible'], $settings_notice['slug']);
		        delete_transient('ocssl_settings_notice');
		        if (WP_DEBUG) {
		            error_log('OCSSL admin_notices: Rendered settings saved notice');
		        }
		    }
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
		            return '';
		        }
		    }
		    
		    if (empty($message)) {
		        return '';
		    }
		    
		    $type = in_array($type, ['success', 'error', 'warning', 'info']) ? $type : 'success';
		    $slug = $slug ? sanitize_key($slug) : '';
		    
		    ob_start();
		    ?>
		    <div class="notice notice-<?php echo esc_attr($type); ?> <?php echo $dismissible ? 'is-dismissible' : ''; ?> notice-one-click-ssl" <?php echo $slug ? 'data-notice="' . esc_attr($slug) . '"' : ''; ?>>
		        <p>
		            <?php
		            switch ($type) {
		                case 'error':
		                    echo '<i class="fa fa-times fa-fw"></i> ';
		                    break;
		                case 'warning':
		                    echo '<i class="fa fa-exclamation-triangle fa-fw"></i> ';
		                    break;
		                case 'success':
		                case 'info':
		                    echo '<i class="fa fa-check fa-fw"></i> ';
		                    break;
		            }
		            echo wp_kses_post($message); // Allow HTML in messages (e.g., links)
		            ?>
		        </p>
		    </div>
		    <?php
		    return ob_get_clean();
		}
		
		// Replace the make_request method
        function make_request($url = null, $username = null, $password = null, $force_credentials = false, $expect_json = true) {
		    global $ocssl_http_code;

		    // Use the query string endpoint for SSL checks
		    if (empty($url)) {
		        $url = is_multisite() && is_network_admin() 
		            ? add_query_arg('ocssl_check', '1', network_home_url('/', 'https')) 
		            : add_query_arg('ocssl_check', '1', home_url('/', 'https'));
		    }

		    $timeout = 10;
		    $body = false;

		    $args = array(
		        'timeout'      => $timeout,
		        'httpversion'  => '1.1',
		        'sslverify'    => true,
		        'method'       => 'GET',
		        'headers'      => array(
		            'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url'),
		            'Accept'     => $expect_json ? 'application/json' : 'text/html, */*',
		        ),
		    );

		    // Use stored credentials only if explicitly requested or if no credentials provided and Basic Auth is required
		    $use_stored_credentials = false;
		    if (empty($username) && empty($password) && !$force_credentials) {
		        $stored_username = get_option('ocssl_auth_username');
		        $stored_password = get_option('ocssl_auth_password');
		        $basic_auth_required = get_option('ocssl_basic_auth_required', false);
		        if ($basic_auth_required && !empty($stored_username) && !empty($stored_password)) {
		            $username = $stored_username;
		            $password = $stored_password;
		            $use_stored_credentials = true;
		        }
		    }

		    // Add Basic Authentication if credentials are provided or stored
		    if (!empty($username) && !empty($password)) {
		        $args['headers']['Authorization'] = 'Basic ' . base64_encode($username . ':' . $password);
		    }

		    // Log request details
		    if (WP_DEBUG) {
		        error_log('OCSSL make_request args: ' . print_r([
		            'url' => $url,
		            'username' => $username ?: 'none',
		            'use_stored_credentials' => $use_stored_credentials,
		            'expect_json' => $expect_json,
		            'headers' => isset($args['headers']) ? $args['headers'] : [],
		        ], true));
		    }

		    $response = wp_remote_get($url, $args);
		    if (WP_DEBUG) {
		        error_log('OCSSL make_request raw response: ' . json_encode($response));
		    }

		    $needs_auth = false;
		    $error_message = null;

		    if (is_wp_error($response)) {
		        $ocssl_http_code = 0;
		        $error_message = $response->get_error_message();
		    } else {
		        $ocssl_http_code = wp_remote_retrieve_response_code($response);
		        $headers = wp_remote_retrieve_headers($response);
		        if ($ocssl_http_code == 401 && isset($headers['www-authenticate']) && stripos($headers['www-authenticate'], 'Basic') !== false) {
		            $needs_auth = true;
		            update_option('ocssl_basic_auth_required', true);
		        } elseif ($ocssl_http_code == 200) {
		            $body = wp_remote_retrieve_body($response);
		            if ($expect_json) {
		                $json = json_decode($body, true);
		                if (json_last_error() === JSON_ERROR_NONE && isset($json['success']) && $json['success'] === true) {
		                    $body = $json;
		                    if (!empty($username) && !empty($password)) {
		                        // Save credentials only if they worked
		                        update_option('ocssl_auth_username', sanitize_text_field($username));
		                        update_option('ocssl_auth_password', $password);
		                        update_option('ocssl_basic_auth_required', true);
		                        if (WP_DEBUG) {
		                            error_log('OCSSL Saved Credentials: username=' . $username);
		                        }
		                    }
		                } else {
		                    $ocssl_http_code = 0;
		                    $error_message = 'Invalid JSON response from SSL check endpoint.';
		                }
		            } else {
		                // For non-JSON responses (e.g., scanner), return the raw body
		                if (!empty($username) && !empty($password)) {
		                    update_option('ocssl_auth_username', sanitize_text_field($username));
		                    update_option('ocssl_auth_password', $password);
		                    update_option('ocssl_basic_auth_required', true);
		                    if (WP_DEBUG) {
		                        error_log('OCSSL Saved Credentials: username=' . $username);
		                    }
		                }
		            }
		        }
		    }

		    $response_data = array(
		        'code'         => $ocssl_http_code,
		        'body'         => $body,
		        'needs_auth'   => $needs_auth,
		        'error_message' => $error_message,
		        'url'          => $url,
		        'headers'      => isset($headers) ? $headers->getAll() : [],
		    );

		    // Log response details
		    if (WP_DEBUG) {
		        error_log('OCSSL make_request response: ' . print_r($response_data, true));
		    }

		    return $response_data;
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
		    $url = is_multisite() && is_network_admin() 
		        ? add_query_arg('ocssl_check', '1', network_home_url('/', 'https')) 
		        : add_query_arg('ocssl_check', '1', home_url('/', 'https'));
		    
		    if ($response = $this->make_request($url, null, null, false, true)) {
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

            // Get credentials from POST data
            $username = isset($_POST['auth_username']) ? sanitize_text_field($_POST['auth_username']) : null;
            $password = isset($_POST['auth_password']) ? $_POST['auth_password'] : null;

            // Log credentials for debugging
            if (WP_DEBUG) {
                error_log('OCSSL AJAX Credentials: username=' . ($username ?: 'none') . ', password=' . ($password ? '[provided]' : 'none'));
            }

            // Make the request to the custom endpoint
            $response = $this->make_request(null, $username, $password, true);

            $ocssl_http_code = $response['code'];

            if ($response['code'] == 200 && is_array($response['body']) && isset($response['body']['success']) && $response['body']['success'] === true) {
                $reply = array(
                    'success'    => true,
                    'http_code'  => $ocssl_http_code,
                    'message'    => __('SSL check successful.', 'one-click-ssl'),
                );
            } else {
                if ($response['needs_auth'] && empty($username) && empty($password)) {
                    $error = '<i class="fa fa-lock"></i> ' . __('Basic Authentication detected and SSL cannot be enabled. To bypass, enter your htpasswd username and password below. This is a secure form.', 'one-click-ssl');
                    $reply = array(
                        'success'    => false,
                        'needs_auth' => true,
                        'http_code'  => $ocssl_http_code,
                        'error'      => $error,
                    );
                } else {
                    $error = sprintf(
                        '<i class="fa fa-times"></i> ' . __('SSL check failed with response code %s.', 'one-click-ssl'),
                        '<strong>' . $ocssl_http_code . '</strong>'
                    );
                    if (!empty($username) && !empty($password)) {
                        $error = '<i class="fa fa-times"></i> ' . __('Incorrect username or password for Basic Authentication. Please try again or check your .htpasswd settings.', 'one-click-ssl');
                    }
                    if ($response['error_message']) {
                        $error .= ' ' . __('Error details:', 'one-click-ssl') . ' ' . esc_html($response['error_message']);
                    }
                    $reply = array(
                        'success'    => false,
                        'needs_auth' => false,
                        'http_code'  => $ocssl_http_code,
                        'error'      => $error,
                    );
                }
            }

            if (WP_DEBUG) {
                error_log('OCSSL ajax_check_ssl_support reply: ' . print_r($reply, true));
            }

            $process = ob_get_clean();
            wp_send_json($reply);
        }
		
		function ajax_enable_ssl() {
            check_ajax_referer('enable_ssl', 'security');

            if (!current_user_can('manage_options')) {
                wp_die(__('You do not have permission', 'one-click-ssl'));
            }

            // Get credentials from POST data
            $username = isset($_POST['auth_username']) ? sanitize_text_field($_POST['auth_username']) : null;
            $password = isset($_POST['auth_password']) ? $_POST['auth_password'] : null;

            // Verify SSL support with provided or stored credentials
            $response = $this->make_request(null, $username, $password);
            if ($response['code'] != 200 || !isset($response['body']['success']) || $response['body']['success'] !== true) {
                wp_send_json_error([
                    'message' => __('Failed to verify SSL support. Please check your credentials or server configuration.', 'one-click-ssl'),
                    'http_code' => $response['code'],
                    'needs_auth' => $response['needs_auth'],
                ]);
            }

            // Enable SSL
            if (is_multisite()) {
                update_site_option('ocssl_global', 1);
                update_site_option('ocssl_areas', 'all');
            } else {
                update_option('ocssl', 1);
                update_option('ocssl_areas', 'all');
            }
                
            wp_cache_flush();
            
            wp_send_json_success([
                'message' => __('SSL enabled successfully.', 'one-click-ssl'),
                'redirect' => is_multisite() ? network_admin_url('admin.php?page=one-click-ssl') : admin_url('admin.php?page=one-click-ssl'),
            ]);
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
		        $scanurl = sanitize_text_field($_POST['scanurl']);
		        // Ensure scanurl is a valid path, not a full URL
		        if (!preg_match('/^https?:\/\//i', $scanurl)) {
		            $url .= ltrim($scanurl, '/');
		        } else {
		            // If a full URL is provided, use it directly after sanitization
		            $url = esc_url_raw($scanurl, ['https']);
		        }
		    }
		    
		    $output = '';
		    
		    if ($response = $this->make_request($url, null, null, false, false)) {                
		        if (!empty($response) && $response['code'] == 200) {                    
		            $pattern = '/<(script|link|base|img|form)\s[^>]*\s(href|src|action)=([\'"]?)(http:\/\/[^>\s\'"]+)(\3)/i';
		            preg_match_all($pattern, $response['body'], $matches);
		            
		            if (!empty($matches[4])) {
		                // Filter out SVG namespace and invalid URLs, then deduplicate
		                $insecure = array_filter(array_unique($matches[4]), function($url) {
		                    return strpos($url, 'w3.org/2000/svg') === false && preg_match('/http:\/\/[^\/]+\.[^\/]+/', $url);
		                });
		                
		                if (!empty($insecure)) {
		                    $success = false;
		                    
		                    $output .= '<div class="alert alert-warning">';
		                    $output .= '<i class="fa fa-exclamation-triangle fa-fw"></i> ' . sprintf(__('%s Insecure resources found on the URL, make them https:// for SSL to validate', 'one-click-ssl'), count($insecure));
		                    
		                    $output .= '<ul>';
		                    foreach ($insecure as $insecure_url) {
		                        $output .= '<li>' . esc_url($insecure_url) . '</li>';
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
		                $success = true;
		                $insecure = false;
		                
		                $output .= '<div class="alert alert-success">';
		                $output .= '<i class="fa fa-check fa-fw"></i> ' . __('No insecure resources found, SSL will validate!', 'one-click-ssl');
		                $output .= '</div>';
		            }
		        } else {
		            $success = false;
		            $insecure = false;
		            $error_message = $response['error_message'] ?: sprintf(__('URL could not be loaded - Code %s', 'one-click-ssl'), $response['code']);
		            if ($response['needs_auth']) {
		                $error_message = __('Basic Authentication required. Please provide credentials in the SSL check.', 'one-click-ssl');
		            }
		            $output .= '<div class="alert alert-danger"><i class="fa fa-times fa-fw"></i> ' . esc_html($error_message) . '</div>';
		        }
		    } else {
		        $success = false;
		        $insecure = false;
		        $output .= '<div class="alert alert-danger"><i class="fa fa-times fa-fw"></i> ' . __('Request failed, please try again.', 'one-click-ssl') . '</div>';
		    }
		    
		    $reply = array(
		        'success' => $success,
		        'insecure' => $insecure,
		        'output' => $output
		    );
		    
		    $process = ob_get_clean();
		    echo json_encode($reply);
		    
		    exit();
		    die();
		}
		
		public function dismiss_smart_rating() {
		    check_ajax_referer('ocssl_dismiss_notice', 'nonce');
		    
		    if (!current_user_can('manage_options')) {
		        wp_send_json_error('Permission denied');
		    }
		    
		    update_option('one_click_ssl_smart_rating_dismissed', true);
		    update_option('ocssl_dismissed-ratereview', 1); // Align with other notices
		    wp_send_json_success();
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
				'/<link\s+(?:(?!>).)*?href\s*=\s*([\'"])\Khttp:\/\/(?=[^\'"]+)/i',
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


        
	    public function save_check_settings() {
            if (!is_admin() || empty($_POST)) {
                return;
            }

            if (!check_admin_referer('ocssl-settings', 'security')) {
                wp_die(__('Security check failed', 'one-click-ssl'));
            }

            // Determine correct update function for single vs network
            $save_fn = ( is_multisite() && is_network_admin() )
                ? 'update_site_option'
                : 'update_option';

            // Reset defaults
            $save_fn('ocssl', 0);
            $save_fn('ocssl_global', 0);
            $save_fn('ocssl_nonsslredirect', 0);
            $save_fn('ocssl_toolsmenu', 0);

            // Save each submitted field
            foreach ($_POST as $pkey => $pval) {
                call_user_func(
                    $save_fn,
                    sanitize_key($pkey),
                    sanitize_text_field($pval)
                );
            }

            // Determine redirect URL
            $ocssl_toolsmenu = !empty($_POST['ocssl_toolsmenu']) ? 1 : 0;
            if ($ocssl_toolsmenu) {
                call_user_func($save_fn, 'ocssl_toolsmenu', 1);
                $url = is_multisite()
                    ? network_admin_url('settings.php?page=one-click-ssl')
                    : admin_url('tools.php?page=one-click-ssl');
            } else {
                call_user_func($save_fn, 'ocssl_toolsmenu', 0);
                $url = is_multisite()
                    ? network_admin_url('admin.php?page=one-click-ssl')
                    : admin_url('admin.php?page=one-click-ssl');
            }

            wp_cache_flush();
            $this->check_ssl();
            
            // Queue settings saved notice
            set_transient('ocssl_settings_notice', [
                'message'     => __('Settings have been saved', 'one-click-ssl'),
                'type'        => 'success',
                'dismissible' => true,
                'slug'        => 'settings-saved'
            ], 30);
            
            do_action('ocssl_settings_saved', $_POST);

            // Redirect to prevent resubmission
            if (!wp_doing_ajax()) {
                wp_redirect($url);
                exit;
            }
        }

		public function dismiss_notice() {
		    check_ajax_referer('ocssl_dismiss_notice', 'nonce');
		    
		    if (!current_user_can('manage_options')) {
		        wp_send_json_error('Permission denied');
		    }
		    
		    $slug = !empty($_POST['slug']) ? sanitize_key($_POST['slug']) : '';
		    if ($slug) {
		        update_option('ocssl_dismissed-' . $slug, 1);
		        if ($slug === 'ratereview') {
		            update_option('one_click_ssl_smart_rating_dismissed', true);
		        }
		        wp_send_json_success();
		    }
		    
		    wp_send_json_error('Invalid slug');
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
	add_action('after_theme_setup', array($ocssl, 'init_textdomain'), 10, 1);
	add_action('admin_init', array($ocssl, 'custom_redirect'), 10, 1);
	add_action('admin_head', array($ocssl, 'admin_head'), 10, 1);
	
	if (is_multisite()) {
		add_action('network_admin_menu', array($ocssl, 'admin_menu'), 10, 1);
	} else {
		add_action('admin_menu', array($ocssl, 'admin_menu'), 10, 1);
	}

	add_action('admin_head',  [$ocssl, 'remove_dashboard']);
		
	add_action('admin_enqueue_scripts', array($ocssl, 'admin_enqueue_scripts'), 10, 1);
	add_action('admin_notices', array($ocssl, 'admin_notices'), 10, 1);

	if ( is_multisite() ) {
	    add_action( 'network_admin_notices', array( $ocssl, 'admin_notices' ) );
	} 
    add_action( 'wp_ajax_one_click_ssl_dismiss_smart_rating', array( $ocssl, 'dismiss_smart_rating' ) );

    add_action('wp_ajax_ocssl_dismiss_notice', array($ocssl, 'dismiss_notice'));



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
	
	add_action('init', 'ocssl_initialize', 5);

	function ocssl_initialize() {
	    // Make sure not to re-include plugin.php if it's already included
	    if (!function_exists('get_plugin_data')) {
	        require_once(ABSPATH . 'wp-admin/includes/plugin.php');
	    }
	    
	    global $ocssl;
        $ocssl->load_plugin_data();
	    
	}
}
