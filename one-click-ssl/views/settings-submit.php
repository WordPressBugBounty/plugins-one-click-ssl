<!-- One Click SSL Settings Submit -->

<?php
        
if (!defined('ABSPATH')) exit; // Exit if accessed directly

?>

<div class="submitbox" id="submitpost">
        <div id="minor-publishing">
                <div id="misc-publishing-actions">
                        <div class="misc-pub-section">
                                <?php if (is_multisite() && is_network_admin()) : ?>
                                        <a href="<?php echo network_admin_url('index.php?page=one-click-ssl-setup'); ?>"><i class="fa fa-cogs fa-fw"></i> <?php _e('Go to Setup', 'one-click-ssl'); ?></a>
                                <?php else : ?>
                                        <a href="<?php echo admin_url('index.php?page=one-click-ssl-setup'); ?>"><i class="fa fa-cogs fa-fw"></i> <?php _e('Go to Setup', 'one-click-ssl'); ?></a>
                                <?php endif; ?>
                        </div>
                        <?php
                        if (is_multisite() && is_network_admin()) {
                                $ocssl_debug_enabled = (bool) get_site_option('ocssl_debug', false);
                        } else {
                                $ocssl_debug_enabled = (bool) get_option('ocssl_debug', false);
                        }

                        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
                                if (is_string(WP_DEBUG_LOG)) {
                                        $ocssl_debug_log_path = WP_DEBUG_LOG;
                                } else {
                                        $ocssl_debug_log_path = trailingslashit(WP_CONTENT_DIR) . 'debug.log';
                                }
                        } else {
                                $ocssl_debug_log_path = ini_get('error_log');

                                if (empty($ocssl_debug_log_path)) {
                                        $ocssl_debug_log_path = trailingslashit(WP_CONTENT_DIR) . 'debug.log';
                                }
                        }

                        if (function_exists('wp_normalize_path')) {
                                $ocssl_normalized_log_path = wp_normalize_path($ocssl_debug_log_path);
                                $ocssl_normalized_abspath = wp_normalize_path(ABSPATH);
                        } else {
                                $ocssl_normalized_log_path = str_replace('\\', '/', $ocssl_debug_log_path);
                                $ocssl_normalized_abspath = str_replace('\\', '/', ABSPATH);
                        }

                        if (strpos($ocssl_normalized_log_path, $ocssl_normalized_abspath) === 0) {
                                $ocssl_display_log_path = ltrim(substr($ocssl_normalized_log_path, strlen($ocssl_normalized_abspath)), '/');
                        } else {
                                $ocssl_display_log_path = $ocssl_normalized_log_path;
                        }
                        ?>
                        <?php
                        $ocssl_debug_help_text_html = sprintf(
                                __('Log detailed diagnostic messages to help troubleshoot. Disable if not needed. View logs in <code>%s</code>', 'one-click-ssl'),
                                esc_html($ocssl_display_log_path)
                        );

                        $ocssl_debug_help_text_plain = wp_strip_all_tags($ocssl_debug_help_text_html);
                        ?>
                        <div class="misc-pub-section misc-pub-section-last ocssl-debug-toggle">
                                <div class="ocssl-debug-toggle__control">
                                        <label for="ocssl_debug" class="ocssl-debug-toggle__label">
                                                <input type="checkbox" name="ocssl_debug" id="ocssl_debug" value="1" <?php checked($ocssl_debug_enabled); ?> />
                                                <span class="ocssl-debug-toggle__label-text">
                                                        <i class="fa fa-bug" aria-hidden="true"></i>
                                                        <?php _e('Turn on debugging', 'one-click-ssl'); ?>
                                                </span>
                                        </label>
                                        <span class="ocssl-debug-toggle__help" role="button" tabindex="0" aria-label="<?php echo esc_attr($ocssl_debug_help_text_plain); ?>">
                                                <span class="ocssl-debug-toggle__help-icon" aria-hidden="true">?</span>
                                                <span class="ocssl-debug-toggle__tooltip" role="tooltip"><?php echo wp_kses_post($ocssl_debug_help_text_html); ?></span>
                                        </span>
                                </div>
                        </div>
                </div>
        </div>
        <div id="major-publishing-actions">
                <div id="publishing-action">
                        <button class="button-primary button button-large" type="submit" name="submit" value="1">
                                <i class="fa fa-check fa-fw"></i> <?php _e('Save Configuration', 'one-click-ssl'); ?>
                        </button>
                </div>
                <br class="clear" />
        </div>
</div>