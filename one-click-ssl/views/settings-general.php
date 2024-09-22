<!-- One Click SSL Settings General -->

<?php
	
if (!$has_ssl = $this -> has_ssl_support()) {
	update_option('ocssl', 0, true);
	
	$message = __('It appears like your server does not support SSL, please ask your hosting provider.', 'one-click-ssl');
	$this -> render_message($message, 'warning');
}

$ocssl = get_option('ocssl');
$ocssl_areas = get_option('ocssl_areas');	
$ocssl_nonsslredirect = get_option('ocssl_nonsslredirect');
$ocssl_toolsmenu = get_option('ocssl_toolsmenu');	
	
?>

<table class="form-table">
	<tbody>
		<tr>
			<th><label for="ocssl"><?php _e('Enable SSL?', 'one-click-ssl'); ?></label></th>
			<td>
				<label><input <?php disabled($has_ssl, false); ?> <?php checked($ocssl, 1); ?> type="checkbox" name="ocssl" value="1" id="ocssl" /> <?php _e('Yes, enable SSL and redirect all URLs.', 'one-click-ssl'); ?></label>
				<span class="howto"><?php _e('Turn this on to globally redirect all URLs and resources', 'one-click-ssl'); ?></span>
			</td>
		</tr>
	</tbody>
</table>

<div id="ocssl_div" style="display:<?php echo (!empty($ocssl)) ? 'block' : 'none'; ?>;">
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

<div id="ocssloff_div" style="display:<?php echo (empty($ocssl)) ? 'block' : 'none'; ?>">
	<table class="form-table">
		<tbody>
			<tr>
				<th><label for="ocssl_nonsslredirect"><?php _e('Redirect to Non-SSL', 'one-click-ssl'); ?></label></th>
				<td>
					<label><input <?php checked($ocssl_nonsslredirect, 1); ?> type="checkbox" name="ocssl_nonsslredirect" value="1" id="ocssl_nonsslredirect" /> <?php _e('Yes, redirect all pages to non-SSL', 'one-click-ssl'); ?></label>
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
				<label><input <?php echo (!empty($ocssl_toolsmenu)) ? 'checked="checked"' : ''; ?> type="checkbox" name="ocssl_toolsmenu" value="1" id="ocssl_toolsmenu" /> <?php _e('Move the WordPress admin menu under Tools.', 'one-click-ssl'); ?></label>
				<span class="howto"><?php _e('Enable this option to move the admin menu item under Tools in your WordPress dashboard.', 'one-click-ssl'); ?></span>
			</td>
		</tr>
	</tbody>
</table>
