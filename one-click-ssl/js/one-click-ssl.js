(function($) {
        
    $.fn.ocssl_step1 = function() {
        var $button1 = this,
            $loading = $button1.find('.loading'),
            $button2 = $('button#one-click-ssl-step2'),
            $success = $('#ocssl-step1-success'),
            $failure = $('#ocssl-step1-failure'),
            $failurealert = $failure.find('.alert-danger'),
            $override = $('#ocssl-override'),
            $authform = $('#ocssl-auth-form');

        // Reset UI
        $success.hide();
        $failure.hide();
        $override.prop('checked', false);
        $button1.prop('disabled', true).removeClass('animated tada');
        $loading.show();
        $button2.prop('disabled', true).removeClass('animated tada');
        // Only remove auth form if no credentials are being provided to avoid losing input values
        if ($authform.length && !$('#ocssl-auth-username').val() && !$('#ocssl-auth-password').val()) {
            console.log('Removing existing auth form as no credentials provided');
            $authform.remove();
        }

        // Prepare data
        var data = {
            action: 'ocssl_check_ssl_support',
            security: ocssl.ajaxnonce.check_ssl_support
        };

        // Add credentials if provided and non-empty
        var $usernameInput = $('#ocssl-auth-username');
        var $passwordInput = $('#ocssl-auth-password');
        var username = $usernameInput.val();
        var password = $passwordInput.val();

        // Log input state for debugging
        console.log('Username Input:', $usernameInput.length ? 'Exists' : 'Missing', 'Value:', username || 'empty');
        console.log('Password Input:', $passwordInput.length ? 'Exists' : 'Missing', 'Value:', password ? '[provided]' : 'empty');

        if ($usernameInput.length && $passwordInput.length && username && password) {
            data.auth_username = username;
            data.auth_password = password;
        } else if ($usernameInput.length || $passwordInput.length) {
            // Warn if inputs exist but are empty
            console.warn('Credentials incomplete: username or password is empty');
        }

        $.ajax({
            url: ajaxurl,
            type: "POST",
            dataType: "json",
            data: data
        }).done(function(data, textStatus, jqXHR) {
            console.log('OCSSL Step 1 Response:', data);
            $loading.hide();
            $button1.prop('disabled', false);

            if (typeof data !== 'object' || data === null) {
                console.error('Invalid response format:', data);
                $failurealert.html('<i class="fa fa-times"></i> Invalid response from server. Please try again.');
                $failure.show();
                return;
            }

            if (typeof data.success !== "undefined" && data.success === true) {
                // Success, SSL is supported!
                $button2.prop('disabled', false).addClass('animated tada');
                $success.show();
            } else {
                $failurealert.html(data.error || '<i class="fa fa-times"></i> Unknown error occurred.');
                if (data.needs_auth && !data.auth_username && !data.auth_password) {
                    // Show authentication form only if no credentials were provided
                    if ($('#ocssl-auth-form').length) {
                        console.warn('Auth form already exists, skipping append');
                    } else {
                        var authFormHtml = '<form id="ocssl-auth-form" style="margin-top:20px;">' +
                            '<p><label for="ocssl-auth-username">' + ocssl.username_label + '</label><br>' +
                            '<input type="text" id="ocssl-auth-username" name="auth_username" class="regular-text" /></p>' +
                            '<p><label for="ocssl-auth-password">' + ocssl.password_label + '</label><br>' +
                            '<input type="password" id="ocssl-auth-password" name="auth_password" class="regular-text" /></p>' +
                            '<p><button type="button" class="button button-secondary" id="ocssl-auth-retry">' + ocssl.retry_button + '</button></p>' +
                            '</form>';
                        // Insert form after the .alert-danger element
                        if ($failurealert.length) {
                            $failurealert.after(authFormHtml);
                            console.log('Authentication form inserted after .alert-danger');
                        } else {
                            console.warn('No .alert-danger element found, falling back to prepend');
                            $failure.prepend(authFormHtml);
                        }
                        console.log('Authentication form added to DOM');
                    }
                    // Bind retry button using event delegation
                    $failure.off('click', '#ocssl-auth-retry').on('click', '#ocssl-auth-retry', function(e) {
                        e.preventDefault();
                        var retryUsername = $('#ocssl-auth-username').val();
                        var retryPassword = $('#ocssl-auth-password').val();
                        console.log('Retry Clicked - Username:', retryUsername || 'empty', 'Password:', retryPassword ? '[provided]' : 'empty');
                        if (!retryUsername || !retryPassword) {
                            $failurealert.html('<i class="fa fa-times"></i> Please enter both username and password.');
                            return;
                        }
                        $button1.trigger('click');
                    });
                } else if (data.needs_auth) {
                    // Credentials were provided but failed
                    $failurealert.html('<i class="fa fa-times"></i> Incorrect username or password. Please try again or check your .htpasswd settings.');
                }
                $failure.show();
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.log('OCSSL Step 1 AJAX Failed:', textStatus, errorThrown, jqXHR.responseText);
            $loading.hide();
            $button1.prop('disabled', false);
            $failurealert.html('<i class="fa fa-times"></i> AJAX request failed: ' + textStatus);
            $failure.show();
        });
    }

    // Rest of the JavaScript remains unchanged
    $.fn.ocssl_step2 = function() {
        var $button2 = this,
            $loading = $button2.find('.loading'),
            $success = $('#ocssl-step2-success'),
            $failure = $('#ocssl-step2-failure'),
            $failurealert = $failure.find('.alert-danger');

        if (!confirm(ocssl.settingswarning)) {
            return false;
        }

        // Reset UI
        $success.hide();
        $failure.hide();
        $button2.prop('disabled', true).removeClass('animated tada');
        $loading.show();

        // Prepare data
        var data = {
            action: 'ocssl_enable_ssl',
            security: ocssl.ajaxnonce.enable_ssl
        };

        // Include credentials if provided in the auth form
        var $usernameInput = $('#ocssl-auth-username');
        var $passwordInput = $('#ocssl-auth-password');
        var username = $usernameInput.val();
        var password = $passwordInput.val();

        // Log input state for debugging
        console.log('Step 2 Username Input:', $usernameInput.length ? 'Exists' : 'Missing', 'Value:', username || 'empty');
        console.log('Step 2 Password Input:', $passwordInput.length ? 'Exists' : 'Missing', 'Value:', password ? '[provided]' : 'empty');

        if ($usernameInput.length && $passwordInput.length && username && password) {
            data.auth_username = username;
            data.auth_password = password;
        }

        $.ajax({
            url: ajaxurl,
            type: "POST",
            dataType: "json",
            data: data
        }).done(function(data, textStatus, jqXHR) {
            console.log('OCSSL Step 2 Response:', data);
            $loading.hide();
            $button2.prop('disabled', false);

            if (typeof data !== 'object' || data === null) {
                console.error('Invalid response format:', data);
                $failurealert.html('<i class="fa fa-times"></i> Invalid response from server. Please try again.');
                $failure.show();
                return;
            }

            if (data.success) {
                $success.show();
                // Redirect to settings page
                if (data.data && data.data.redirect) {
                    console.log('Redirecting to:', data.data.redirect);
                    document.location = data.data.redirect;
                } else {
                    console.warn('No redirect URL provided, falling back to default');
                    document.location = ocssl.settings_url;
                }
            } else {
                $failurealert.html((data.data && data.data.message) || '<i class="fa fa-times"></i> Failed to enable SSL.');
                if (data.data && data.data.needs_auth) {
                    $failurealert.html('<i class="fa fa-lock"></i> Authentication required. Please provide valid credentials.');
                }
                $failure.show();
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.log('OCSSL Step 2 AJAX Failed:', textStatus, errorThrown, jqXHR.responseText);
            $loading.hide();
            $button2.prop('disabled', false);
            $failurealert.html('<i class="fa fa-times"></i> AJAX request failed: ' + textStatus);
            $failure.show();
        });
    }
    
    $(function() {	
        // Setup Buttons
        $('button#one-click-ssl-step1').on('click', function() {
            $(this).ocssl_step1();
        });
        
        $('button#one-click-ssl-step2').on('click', function() {
            $(this).ocssl_step2();
        });
        
        $('#ocssl-override').on('click', function() {
            $button2 = $('button#one-click-ssl-step2');
            if ($(this).is(':checked')) {
                $button2.prop('disabled', false).addClass('animated tada');
            } else {
                $button2.prop('disabled', true).removeClass('animated tada');
            }
        });
            
        // When the enable SSL checkbox is clicked
        $('.one-click-ssl-settings #ocssl').on('click', function(e) {
            if ($(this).is(':checked')) {
                $('#ocssl_div').show();
                $('#ocssloff_div').hide();
            } else {
                $('#ocssl_div').hide();
                $('#ocssloff_div').show();
            }
        });	
        
        // Show a warning message when enabling SSL
        if (typeof ocssl.is_ssl == "undefined" || ocssl.is_ssl == false) {
            $('#one-click-ssl-settings-form').on('submit', function(e) {
                if ($('#ocssl').is(':checked') || $('#ocssl_global').is(':checked')) {
                    if (!confirm(ocssl.settingswarning)) {
                        return false;
                    }
                }
            });
        }
        
        // Scanner 		
        $scanbutton = $('button#scanbutton');
        $scanurl = $('input#scanurl');
        $scanresults = $('div#scanresults');
        
        $scanurl.on('keypress', function (e) {
            if (e.which === 13) {
                $scanbutton.trigger('click');
                return false;
            }
        });
        
        $scanbutton.on('click', function() {			
            $scanresults.hide();
            $scanbutton.prop('disabled', true).find('i.fa').addClass('fa-spin');			
            
            $.ajax({
                url: ajaxurl + '?action=ocssl_scan&security=' + ocssl.ajaxnonce.scan,
                type: "POST",
                dataType: "json",
                data: {
                    scanurl: $scanurl.val()
                }
            }).done(function (data, textStatus, jqXHR) {				
                $scanbutton.prop('disabled', false).find('i.fa').removeClass('fa-spin');
                $scanresults.html(data.output).show();
                
            }).fail(function (jqXHR, textStatus, errorThrown) {
                // Ajax call failed...	
                $scanbutton.prop('disabled', false).find('i.fa').removeClass('fa-spin');
                alert('Ajax call failed, try again.');
            });
        });
    });
    
    // Hook into the "notice-my-class" class we added to the notice, so
    // Only listen to YOUR notices being dismissed
    jQuery(document).ready(function($) {
        $(document).on('click', '.notice-one-click-ssl.is-dismissible .notice-dismiss, .notice-one-click-ssl .my-custom-dismiss-button', function(e) {
            e.preventDefault();
            var $notice = $(this).closest('.notice-one-click-ssl');
            var slug = $notice.data('notice') || $(this).data('slug');
            if (slug) {
                $.post(ajaxurl, {
                    action: slug === 'ratereview' ? 'one_click_ssl_dismiss_smart_rating' : 'ocssl_dismiss_notice',
                    nonce: ocssl.ajaxnonce.dismiss,
                    slug: slug
                }, function(response) {
                    if (response.success) {
                        $notice.fadeOut();
                    } else {
                        console.error('Notice dismissal failed:', response);
                    }
                }).fail(function(jqXHR, textStatus, errorThrown) {
                    console.error('AJAX error:', textStatus, errorThrown);
                });
            }
        });
    });
        
})(jQuery);