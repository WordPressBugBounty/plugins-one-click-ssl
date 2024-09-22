<!-- One Click SSL Settings General -->

<?php
	
if (!$has_ssl = $this -> has_ssl_support()) {
	update_site_option('ocssl_global', 0);
	
	$message = __('It appears like your server does not support SSL, please ask your hosting provider.', 'one-click-ssl');
	$this -> render_message($message, 'warning');
}
	
$ocssl_global = get_site_option('ocssl_global');	
	
?>

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