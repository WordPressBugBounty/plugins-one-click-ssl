<!-- One Click SSL Network Settings -->

<?php
	
if (!defined('ABSPATH')) exit; // Exit if accessed directly

global $post, $post_ID;
$post_ID = 1;

wp_nonce_field('closedpostboxes', 'closedpostboxesnonce', false);
wp_nonce_field('meta-box-order', 'meta-box-order-nonce', false);

?>

<div class="wrap one-click-ssl one-click-ssl-settings">
	<h1><i class="fa fa-lock fa-fw"></i> <?php _e('One Click SSL', 'one-click-ssl'); ?></h1>
	
	<form action="<?php echo network_admin_url('admin.php?page=one-click-ssl'); ?>" name="post" id="one-click-ssl-settings-form" method="post">		
		<?php wp_nonce_field('ocssl-settings', 'security'); ?>

		<div id="poststuff" class="metabox-holder has-right-sidebar">
			<div id="side-info-column" class="inner-sidebar">		
				<?php do_action('submitpage_box'); ?>	
				<?php do_meta_boxes($this -> ocssl_menu, 'side', $post); ?>
			</div>
			<div id="post-body">
				<div id="post-body-content">
					<?php do_meta_boxes($this -> ocssl_menu, 'normal', $post); ?>
				</div>
			</div>
		</div>
	</form>
</div>