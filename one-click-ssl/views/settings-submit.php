<!-- One Click SSL Settings Submit -->

<?php
	
if (!defined('ABSPATH')) exit; // Exit if accessed directly

?>

<div class="submitbox" id="submitpost">
	<div id="minor-publishing">
		<div id="misc-publishing-actions">
			<div class="misc-pub-section misc-pub-section-last">
				<?php if (is_multisite() && is_network_admin()) : ?>
					<a href="<?php echo network_admin_url('index.php?page=one-click-ssl-setup'); ?>"><i class="fa fa-cogs fa-fw"></i> <?php _e('Go to Setup', 'one-click-ssl'); ?></a>
				<?php else : ?>
					<a href="<?php echo admin_url('index.php?page=one-click-ssl-setup'); ?>"><i class="fa fa-cogs fa-fw"></i> <?php _e('Go to Setup', 'one-click-ssl'); ?></a>
				<?php endif; ?>
			</div>
		</div>
	</div>
	<div id="major-publishing-actions">
		<div id="publishing-action">
			<button class="button-primary button button-large" type="submit" name="save" value="1">
				<i class="fa fa-check fa-fw"></i> <?php _e('Save Configuration', 'one-click-ssl'); ?>
			</button>
		</div>
		<br class="clear" />
	</div>
</div>