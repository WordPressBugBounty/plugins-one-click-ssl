(function($) {
		
	$.fn.ocssl_step1 = function() {
		var $button1 = this,
			$loading = $button1.find('.loading'), 
			$button2 = $('button#one-click-ssl-step2'), 
			$success = $('#ocssl-step1-success'), 
			$failure = $('#ocssl-step1-failure'), 
			$failurealert = $failure.find('.alert-danger'),
			$override = $('#ocssl-override');
		
		$success.hide();
		$failure.hide();
		$override.prop('checked', false);
		$button1.prop('disabled', true).removeClass('animated tada');
		$loading.show();
		$button2.prop('disabled', true).removeClass('animated tada');
		
		$.ajax({
			url: ajaxurl + '?action=ocssl_check_ssl_support&security=' + ocssl.ajaxnonce.check_ssl_support,
			type: "POST",
			dataType: "json"
		}).done(function (data, textStatus, jqXHR) {
			$loading.hide();
			$button1.prop('disabled', false);
			
			if (typeof data.success != "undefined" && data.success == true) {
				// Success, SSL is supported!
				$button2.prop('disabled', false).addClass('animated tada');
				$success.show();
			} else {
				// Failed, SSL is not supported
				$failurealert.html(data.error);
				$failure.show();
			}
		}).fail(function (jqXHR, textStatus, errorThrown) {
			// Ajax call failed...	
			alert('Ajax call failed, try again.');
		});
	}
	
	$.fn.ocssl_step2 = function() {
		var $button2 = this, 
			$loading = $button2.find('.loading'),
			$success = $('#ocssl-step2-success'), 
			$failure = $('#ocssl-step2-failure');
			
		if (!confirm(ocssl.settingswarning)) {
			return false;
		}
			
		$button2.prop('disabled', true);
		$loading.show();
		
		$.ajax({
			url: ajaxurl + '?action=ocssl_enable_ssl&security=' + ocssl.ajaxnonce.enable_ssl,
			type: "POST"
		}).done(function (data, textStatus, jqXHR) {
			$loading.hide();
			$button2.prop('disabled', false);
			
			$success.show();
			document.location = ocssl.settings_url;
			
		}).fail(function (jqXHR, textStatus, errorThrown) {
			// Ajax call failed...	
			alert('Ajax call failed, try again.');
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
	$(document).on('click', '.notice-one-click-ssl .notice-dismiss', function () {				
		// Read the "data-notice" information to track which notice
		// is being dismissed and send it via AJAX
		var slug = $(this).closest('.notice-one-click-ssl').data('notice');
		
		// Make an AJAX call
		// Since WP 2.8 ajaxurl is always defined in the admin header and points to admin-ajax.php
		$.ajax(ajaxurl + '?action=ocssl_dismissed_notice&security=' + ocssl.ajaxnonce.dismissed_notice, {
			type: 'POST',
			data: {
				action: 'ocssl_dismissed_notice',
				slug: slug,
			}
		});
	});
	
})(jQuery);