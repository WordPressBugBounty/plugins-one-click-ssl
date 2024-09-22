=== One Click SSL ===
Contributors: contrid
Donate link: https://tribulant.com
Tags: ssl, https, redirect, mixed-content, resources, http, secure, certificate, insecure content
Requires at least: 4.6
Tested up to: 6.6.1
Stable tag: 1.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enable SSL to redirect all pages to SSL and load all resources over SSL.


== Description ==

A simple and easy to use WordPress SSL plugin which will redirect all non-SSL pages to SSL and ensure that all resources on your SSL pages are loaded over SSL as well.

It includes a user-friendly setup wizard upon activation to check if SSL is supported on the hosting/server before it allows the SSL to be enabled and that ensures that the website doesn't become inaccessible if SSL is not supported.


= Plugin Features =

* Check if SSL is supported on hosting/server
* Enable SSL with a single click
* Redirects all non-SSL URLs to https://
* Converts all non-SSL resources (images, scripts, stylesheets, etc.) to https:// on pages
* Redirect to non-SSL if SSL is not enabled

See our <a href="https://tribulant.com/docs/one-click-ssl-plugin/11098">online documentation</a> for more details and detailed instructions.


== Installation ==

Follow these steps to install the plugin:

1. Upload the plugin files to the `/wp-content/plugins/one-click-ssl` directory, or install the plugin through the WordPress plugins screen directly.
1. Activate the plugin through the 'Plugins' screen in WordPress
1. Use the setup screen after activation to enable SSL or go to the One Click SSL admin menu item to enable.


== Frequently Asked Questions ==

= What is SSL? =

SSL stands for Secure Sockets Layer and it is a protocol which encrypts all data in transit on your website to prevent theft, interception or hacking.


= What is required to use SSL? =

You need to have SSL support on your hosting/server. This is done by installing an SSL certificate.


= Is SSL mandatory? =

No, it is not, but for the security and peace of mind of your users, it is highly recommended. Many modern day browsers are warning users about insecure websites, and some search engines rank you lower if you do not activate SSL.


== Screenshots ==

1. Testing utility to check if SSL is supported on the hosting so that the website doesn't become inaccessible.
2. Easily enable SSL with a single click after confirming SSL support.
3. If you are already on SSL (https://) the plugin will tell you that and no action is required.
4. Configure your SSL to run on specific sections and behave in a certain way as required.


== Changelog ==

See all <a href="https://tribulant.com/docs/one-click-ssl-plugin/11098/#doc6">releases and full changelogs</a> in our docs.

= 1.6 =
* FIX: AJAX calls error after update. If you are unable to update your plugins after using v1.5, use FTP to update to this version. In wp-content/plugins, you can either remove the folder for One Click SSL and reinstall in WordPress, or overwrite all files with the files from this archive.

= 1.5 =
* IMPROVE: PHP 8.3 compatibility. Do not use this version. Skip to v1.6.

= 1.4.9 =
* ADD: "Dismiss forever" button on the admin area rating notice to dismiss it forever.
* IMPROVE: Text improvements.
* FIX: Avada theme conflict (critical error when Avada was active).

= 1.4.8 =
* IMPROVE: WordPress 6.1 compatibility.
* IMPROVE: PHP 8.1 compatibility.
* IMPROVE: Text improvements.

= 1.4.7 =
* IMPROVE: Setup page improvements.
* IMPROVE: Security fixes and improvements.

= 1.4.6 =
* IMPROVE: WordPress 5.2 compatibility.
* FIX: Metaboxes not opening/closing.

= 1.4.4 =
* IMPROVE: WordPress 5.0 compatibility.

= 1.4.3 =
* ADD: SSL certificate info/status box.
* IMPROVE: About box on the settings page with useful links.
* IMPROVE: Ask for a rating on WordPress.org after a while.
* IMPROVE: Make SVG elements secure enhancement.

= 1.4.2 =
* ADD: Turn off SSL on deactivation of plugin.
* ADD: Admin notice when not running on SSL (https).
* IMPROVE: Improved insecure resources scanner accuracy.
* IMPROVE: Notice: curl_setopt(): CURLOPT_SSL_VERIFYHOST value 2.

= 1.4.1 =
* ADD: SSL (https) tester to scan the website for insecure resources.

= 1.4 =
* ADD: New settings screen layout with postboxes.
* ADD: Override option when checking SSL support.
* IMPROVE: Load JS/CSS only on One Click SSL sections/screens.
* IMPROVE: Don't check the site title/name when verifying SSL.
* IMPROVE: Update styling for WordPress 4.8+.

= 1.3.1 =
* IMPROVE: Verify that SSL certificate is valid enhancement.
* IMPROVE: Do not check and redirect SSL when SSL support is checked enhancement.
* IMPROVE: Use wp_remote_get() when PHP CURL is unavailable.

= 1.2 =
* ADD: Setting to move the admin menu item under Tools.
* IMPROVE: Apply replace_https to WordPress language_attributes filter hook.
* FIX: Regular expression issue which can break Ajax in some areas.
* FIX: PHP output buffer issue.

= 1.1 =
* ADD: Multi-site network SSL support.
* ADD: Setting to redirect to non-SSL when SSL is turned off.
* FIX: Replace HTTPS breaks on filters with Array/Object data.

= 1.0 =
* Initial release of the plugin.
