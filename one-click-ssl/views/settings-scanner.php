<!-- Insecure Resources Scanner -->

<p class="howto"><?php _e('Scan a URL for insecure resources like images, stylesheets, scripts, etc., which invalidate/break SSL.', 'one-click-ssl'); ?></p>

<table class="form-table">
	<tbody>
		<tr>
			<th><label for=""><?php _e('URL to Scan', 'one-click-ssl'); ?></label></th>
			<td>
				<input type="hidden" name="scanurl_home" value="<?php echo esc_attr(stripslashes(home_url('/'))); ?>" />
				<code><?php echo home_url('/'); ?></code><input type="text" name="scanurl" value="" id="scanurl" class="widefat" style="width:50%;" placeholder="<?php echo esc_attr__('Leave empty for homepage or fill in a slug e.g., contact-us/', 'one-click-ssl'); ?>" />
				<span class="howto"><?php _e('Choose the URL to scan for insecure resources.', 'one-click-ssl'); ?></span>
			</td>
		</tr>
		<tr>
			<th></th>
			<td>
				<button type="button" name="scanbutton" value="1" id="scanbutton" class="button button-primary">
					<i class="fa fa-refresh fa-fw"></i> <?php _e('Scan Now', 'one-click-ssl'); ?></button>
				</button>
			</td>
		</tr>
		<tr>
			<th></th>
			<td>
				<div id="scanresults" style="display:none;">
					<!-- Scan Results Go Here -->
				</div>
			</td>
		</tr>
	</tbody>
</table>
