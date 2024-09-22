<?php
/**
 * About This Version administration panel.
 *
 * @package WordPress
 * @subpackage Administration
 */

/** WordPress Administration Bootstrap */
require_once(ABSPATH . 'wp-admin' . DS . 'admin.php');


?>

<div class="wrap about-wrap one-click-ssl one-click-ssl-setup">
	<h1><?php _e('Welcome to One Click SSL', 'one-click-ssl'); ?></h1>

	<p class="about-text">
		<?php _e('Thank you for installing One Click SSL powered by <a href="https://tribulant.com" target="_blank">Tribulant Software</a>, the ultimate WordPress SSL plugin which will redirect all non-SSL pages to SSL and ensure that all resources on your SSL pages are loaded over SSL as well.', 'one-click-ssl'); ?>
	</p>
	
	<div class="one-click-ssl-badge">
		<div>
			<i class="fa fa-lock fa-fw"></i>
		</div>
		<?php printf(__('Version %s', 'one-click-ssl'), $this -> plugin_version); ?>
	</div>

	<?php $ocssl = get_option('ocssl'); ?>
	<?php if (is_ssl() && !empty($ocssl)) : ?>
		<div class="feature-section one-col has-1-columns">
			<div class="col column">
				<h2><i class="fa fa-check"></i> <?php _e('SSL Already Enabled', 'one-click-ssl'); ?></h2>
	
				<p class="lead-description">
					<?php _e('You are already on SSL (https://) so there is nothing left to do!', 'one-click-ssl'); ?>
				</p>
			</div>
		</div>
	<?php else : ?>
		<div class="feature-section one-col has-1-columns">
			<div class="col column">
				<h2><i class="fa fa-mouse-pointer"></i> <?php _e('Enable SSL With One Click', 'one-click-ssl'); ?></h2>
	
				<p class="lead-description">
					<?php _e('To use SSL, simply follow Step 1 below to check if SSL is supported on your hosting, and if it is, use Step 2 to enable SSL.', 'one-click-ssl'); ?>
				</p>
			</div>
		</div>

		<div class="feature-section two-col has-2-columns">
			<div class="col column">
				<h3><?php _e('Step 1', 'one-click-ssl'); ?></h3>
				
				<p><?php _e('To check if SSL is supported on your hosting, click the "Check SSL Support" button below.', 'one-click-ssl');?></p>
				
				<p>
					<button class="button button-secondary button-hero animated tada" type="button" name="one-click-ssl-step1" id="one-click-ssl-step1">
						<i class="fa fa-question-circle fa-fw"></i> <?php _e('Check SSL Support', 'one-click-ssl'); ?>
						<span class="loading" id="ocssl-step1-loading" style="display:none;">
							<i class="fa fa-spin fa-refresh fa-fw"></i>
						</span>
					</button>
				</p>
				
				<div id="ocssl-step1-success">
					<h3><?php _e('SSL is Supported', 'one-click-ssl'); ?></h3>
					
					<div class="alert alert-success">
						<i class="fa fa-check"></i> <?php _e('SSL is supported on your hosting, you may enable it.', 'one-click-ssl'); ?>
					</div>
				</div>
				
				<div id="ocssl-step1-failure">
					<h3><?php _e('Install/Enable SSL on Hosting', 'one-click-ssl'); ?></h3>
					
					<div class="alert alert-danger">
						<i class="fa fa-times"></i> <?php _e('SSL is not supported, please ask your hosting provider to install and configure SSL.', 'one-click-ssl'); ?>
					</div>
					
					<div class="alert alert-success">
						<i class="fa fa-check fa-fw"></i> <?php _e('Get WordPress hosting with free, auto SSL.', 'one-click-ssl'); ?>
						
						<p><a href="https://tribulant.com/hosting/" target="_blank" class="button button-secondary"><i class="fa fa-server fa-fw"></i> <?php _e('Get Hosting with SSL', 'one-click-ssl'); ?></a></p>
					</div>
					
					<h3><?php _e('OR', 'one-click-ssl'); ?></h3>
					
					<p>
						<label><input type="checkbox" name="ocssl-override" value="1" id="ocssl-override" /> <?php _e('Override, I am sure SSL works (not recommended)', 'one-click-ssl'); ?></label>
					</p>
					
					<p class="howto"><?php echo sprintf(__('This is not recommended and can render your site inaccessible if SSL does not work. Test it first to see if it loads: %s', 'one-click-ssl'), '<a href="' . esc_url(home_url('/', 'https')) . '" target="_blank">' . get_bloginfo('name') . '</a>'); ?></p>
				</div>
			</div>
			<div class="col column">
				<h3><?php _e('Step 2', 'one-click-ssl'); ?></h3>
				
				<p><?php _e('With SSL supported on your hosting, you may click the "Enable SSL" button below.', 'one-click-ssl'); ?></p>
				
				<p>
					<button disabled="disabled" class="button button-primary button-hero" type="button" name="one-click-ssl-step2" id="one-click-ssl-step2">
						<i class="fa fa-shield fa-fw"></i> <?php _e('Enable SSL', 'one-click-ssl'); ?>
						<span class="loading" id="ocssl-step2-loading" style="display:none;">
							<i class="fa fa-spin fa-refresh fa-fw"></i>
						</span>
					</button>
				</p>
				
				<div id="ocssl-step2-success">
					<h3><?php _e('SSL Enabled', 'one-click-ssl'); ?></h3>
					<div class="alert alert-success">
						<i class="fa fa-check"></i> <?php _e('SSL enabled, you will now be redirected, please log in again.', 'one-click-ssl'); ?>
					</div>
				</div>
				
				<div id="ocssl-step2-failure">
					<h3><?php _e('SSL Failed', 'one-click-ssl'); ?></h3>
					<div class="alert alert-danger">
						<i class="fa fa-times"></i> <?php _e('SSL could not be enabled, please try again.', 'one-click-ssl'); ?>
					</div>
				</div>
			</div>
		</div>
	<?php endif; ?>

	<hr />

	<div class="return-to-dashboard">
		<?php if (is_multisite()) : ?>
			<a href="<?php echo network_admin_url('admin.php?page=one-click-ssl'); ?>"><?php _e('Go to SSL Settings', 'one-click-ssl'); ?> <i class="fa fa-arrow-right fa-fw"></i></a>
		<?php else : ?>
			<a href="<?php echo admin_url('admin.php?page=one-click-ssl'); ?>"><?php _e('Go to SSL Settings', 'one-click-ssl'); ?> <i class="fa fa-arrow-right fa-fw"></i></a>
		<?php endif; ?>
	</div>

</div>
