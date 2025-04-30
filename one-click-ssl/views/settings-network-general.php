<!-- One Click SSL Network Settings General -->

<?php
// Check SSL support only if not already enabled
$ocssl_global = get_site_option('ocssl_global');
$has_ssl = $ocssl_global ? true : $this->has_ssl_support();

if (!$has_ssl && !$ocssl_global) {
    $message = __('It appears like your server does not support SSL, please ask your hosting provider.', 'one-click-ssl');
    $this->render_message($message, 'warning');
}

$ocssl_areas = get_site_option('ocssl_areas', 'all');
$ocssl_toolsmenu = get_site_option('ocssl_toolsmenu');
$basic_auth_required = get_option('ocssl_basic_auth_required', false);
?>

<input type="hidden" name="ocssl_form_submitted" value="1" />

<table class="form-table">
    <tbody>
        <tr>
            <th><label for="ocssl_global"><?php _e('Enable SSL Network Wide?', 'one-click-ssl'); ?></label></th>
            <td>
                <label><input <?php disabled($has_ssl, false); ?> <?php checked($ocssl_global, 1); ?> type="checkbox" name="ocssl_global" value="1" id="ocssl_global" /> <?php _e('Yes, enable SSL on all sites on the network.', 'one-click-ssl'); ?></label>
                <span class="howto"><?php _e('By turning this on, SSL will be enabled on all sites on the network.', 'one-click-ssl'); ?></span>
            </td>
        </tr>
    </tbody>
</table>

<div id="ocssl_div" style="display:<?php echo (!empty($ocssl_global)) ? 'block' : 'none'; ?>;">
    <table class="form-table">
        <tbody>
            <tr>
                <th><label for="ocssl_areas_all"><?php _e('SSL Areas', 'one-click-ssl'); ?></label></th>
                <td>
                    <label><input <?php checked($ocssl_areas, "all"); ?> type="radio" name="ocssl_areas" value="all" id="ocssl_areas_all" /> <?php _e('Everywhere', 'one-click-ssl'); ?></label><br/>
                    <label><input <?php checked($ocssl_areas, "admin"); ?> type="radio" name="ocssl_areas" value="admin" id="ocssl_areas_admin" /> <?php _e('Admin Dashboard Only', 'one-click-ssl'); ?></label><br/>
                    <label><input <?php checked($ocssl_areas, "front"); ?> type="radio" name="ocssl_areas" value="front" id="ocssl_areas_front" /> <?php _e('Website Front-end Only', 'one-click-ssl'); ?></label>
                    <span class="howto"><?php _e('Choose where you want http:// URLs to be changed to https://', 'one-click-ssl'); ?></span>
                </td>
            </tr>
        </tbody>
    </table>
</div>

<div id="ocssloff_div" style="display:<?php echo (empty($ocssl_global)) ? 'block' : 'none'; ?>;">
    <table class="form-table">
        <tbody>
            <tr>
                <th><label for="ocssl_nonsslredirect"><?php _e('Redirect to Non-SSL', 'one-click-ssl'); ?></label></th>
                <td>
                    <label><input <?php checked(get_site_option('ocssl_nonsslredirect'), 1); ?> type="checkbox" name="ocssl_nonsslredirect" value="1" id="ocssl_nonsslredirect" /> <?php _e('Yes, redirect all pages to non-SSL', 'one-click-ssl'); ?></label>
                    <span class="howto"><?php _e('With SSL disabled, you can turn on this setting to redirect all https:// pages to non-SSL automatically.', 'one-click-ssl'); ?></span>
                </td>
            </tr>
        </tbody>
    </table>
</div>

<table class="form-table">
    <tbody>
        <tr>
            <th><label for="ocssl_toolsmenu"><?php _e('Admin Menu', 'one-click-ssl'); ?></label></th>
            <td>
                <label><input <?php echo (!empty($ocssl_toolsmenu)) ? 'checked="checked"' : ''; ?> type="checkbox" name="ocssl_toolsmenu" value="1" id="ocssl_toolsmenu" /> <?php _e('Move the WordPress admin menu under Settings.', 'one-click-ssl'); ?></label>
                <span class="howto"><?php _e('Enable this option to move the admin menu item under Settings in your WordPress dashboard.', 'one-click-ssl'); ?></span>
            </td>
        </tr>
    </tbody>
</table>