/**
 * Two-Factor Authentication Admin JavaScript
 *
 * Handles method selector, AJAX user search, TOTP reset,
 * notification controls, and TOTP profile setup
 *
 * @package Vigilante
 */

(function($) {
    'use strict';

    // =========================================================================
    // Admin settings module
    // =========================================================================
    var Vigilante2FA = {
        searchTimeout: null,
        resetSearchTimeout: null,
        minSearchLength: 2,

        init: function() {
            this.bindEvents();
            this.toggleSettingsVisibility();
            this.toggleMethodFields();
        },

        bindEvents: function() {
            var self = this;

            $(document).on('change', '#vigilante_2fa_enabled', function() {
                self.toggleSettingsVisibility();
            });

            $(document).on('change', 'input[name="login_security[two_factor][method]"]', function() {
                self.toggleMethodFields();
            });

            // Exclusion search
            $(document).on('input', '#vigilante_2fa_user_search', function() {
                self.handleUserSearch($(this), '.vigilante-2fa-search-results', 'vigilante_search_users_2fa');
            });
            $(document).on('focus', '#vigilante_2fa_user_search', function() {
                var $r = $(this).siblings('.vigilante-2fa-search-results');
                if ($r.children().length > 0) $r.addClass('active');
            });
            $(document).on('click', '.vigilante-2fa-search-results .search-result-item', function() {
                self.addExcludedUser($(this));
            });
            $(document).on('click', '.vigilante-2fa-excluded-user .remove-user', function() {
                $(this).closest('.vigilante-2fa-excluded-user').remove();
                self.toggleResetButton();
            });

            // Close dropdowns on outside click
            $(document).on('click', function(e) {
                if (!$(e.target).closest('.vigilante-2fa-user-search').length) {
                    $('.vigilante-2fa-search-results, .vigilante-totp-reset-results').removeClass('active');
                }
            });

            // Notification
            $(document).on('click', '#vigilante_2fa_send_notification', function(e) {
                e.preventDefault();
                self.sendNotification($(this));
            });

            // TOTP reset search
            $(document).on('input', '#vigilante_totp_reset_search', function() {
                self.handleResetSearch($(this));
            });
            $(document).on('focus', '#vigilante_totp_reset_search', function() {
                var $r = $(this).siblings('.vigilante-totp-reset-results');
                if ($r.children().length > 0) $r.addClass('active');
            });
            $(document).on('click', '.vigilante-totp-reset-results .search-result-item', function() {
                self.addResetUser($(this));
            });
            $(document).on('click', '.vigilante-totp-reset-selected .remove-user', function() {
                $(this).closest('.vigilante-totp-reset-user').remove();
                self.toggleResetButton();
            });
            $(document).on('click', '#vigilante_totp_reset_btn', function(e) {
                e.preventDefault();
                self.resetTotpUsers($(this));
            });
        },

        toggleSettingsVisibility: function() {
            var enabled = $('#vigilante_2fa_enabled').is(':checked');
            $('.vigilante-2fa-settings-wrapper').toggleClass('vigilante-2fa-settings-disabled', !enabled);
        },

        toggleMethodFields: function() {
            var method = $('input[name="login_security[two_factor][method]"]:checked').val() || 'email';
            $('.vigilante-2fa-method-option').removeClass('selected');
            $('input[name="login_security[two_factor][method]"]:checked').closest('.vigilante-2fa-method-option').addClass('selected');
            $('.vigilante-2fa-totp-only').toggle('totp' === method);
            $('.vigilante-2fa-email-only').toggle('email' === method);
        },

        handleUserSearch: function($input, resultsSelector, action) {
            var self = this;
            var query = $input.val().trim();
            var $results = $input.siblings(resultsSelector || '.vigilante-2fa-search-results');

            if (this.searchTimeout) clearTimeout(this.searchTimeout);
            if (query.length < this.minSearchLength) {
                $results.removeClass('active').empty();
                return;
            }

            $results.addClass('active').html('<div class="searching">' + self.str('searching') + '</div>');

            this.searchTimeout = setTimeout(function() {
                $.post(self.ajaxUrl(), {
                    action: action || 'vigilante_search_users_2fa',
                    nonce: self.nonce(),
                    query: query,
                    exclude: self.getExcludedUserIds()
                }, function(response) {
                    if (response.success && response.data.length > 0) {
                        self.renderResults(response.data, $results);
                    } else {
                        $results.html('<div class="no-results">' + self.str('noUsersFound') + '</div>');
                    }
                });
            }, 300);
        },

        handleResetSearch: function($input) {
            var self = this;
            var query = $input.val().trim();
            var $results = $input.siblings('.vigilante-totp-reset-results');

            if (this.resetSearchTimeout) clearTimeout(this.resetSearchTimeout);
            if (query.length < this.minSearchLength) {
                $results.removeClass('active').empty();
                return;
            }

            $results.addClass('active').html('<div class="searching">' + self.str('searching') + '</div>');

            this.resetSearchTimeout = setTimeout(function() {
                $.post(self.ajaxUrl(), {
                    action: 'vigilante_search_totp_users',
                    nonce: self.nonce(),
                    query: query
                }, function(response) {
                    if (response.success && response.data.length > 0) {
                        self.renderResults(response.data, $results);
                    } else {
                        $results.html('<div class="no-results">No TOTP users found</div>');
                    }
                });
            }, 300);
        },

        renderResults: function(users, $results) {
            var self = this;
            var html = '';
            $.each(users, function(i, u) {
                html += '<div class="search-result-item" data-user-id="' + u.ID + '" data-user-email="' + self.esc(u.user_email) + '" data-user-display="' + self.esc(u.display_name) + '">';
                html += '<img class="user-avatar" src="' + u.avatar + '" alt="">';
                html += '<div class="user-info"><div class="user-name">' + self.esc(u.display_name) + '</div>';
                html += '<div class="user-email">' + self.esc(u.user_email) + '</div></div></div>';
            });
            $results.html(html);
        },

        addExcludedUser: function($item) {
            var uid = $item.data('user-id');
            if ($('.vigilante-2fa-excluded-user[data-user-id="' + uid + '"]').length) return;

            $('.vigilante-2fa-excluded-users').append(
                '<div class="vigilante-2fa-excluded-user" data-user-id="' + uid + '">' +
                '<span class="user-display">' + this.esc($item.data('user-display')) + ' (' + this.esc($item.data('user-email')) + ')</span>' +
                '<button type="button" class="remove-user" aria-label="Remove">&times;</button>' +
                '<input type="hidden" name="login_security[two_factor][excluded_users][]" value="' + uid + '">' +
                '</div>'
            );
            $('#vigilante_2fa_user_search').val('');
            $('.vigilante-2fa-search-results').removeClass('active').empty();
        },

        addResetUser: function($item) {
            var uid = $item.data('user-id');
            if ($('.vigilante-totp-reset-user[data-user-id="' + uid + '"]').length) return;

            $('.vigilante-totp-reset-selected').append(
                '<div class="vigilante-totp-reset-user vigilante-2fa-excluded-user" data-user-id="' + uid + '">' +
                '<span class="user-display">' + this.esc($item.data('user-display')) + ' (' + this.esc($item.data('user-email')) + ')</span>' +
                '<button type="button" class="remove-user" aria-label="Remove">&times;</button></div>'
            );
            $('#vigilante_totp_reset_search').val('');
            $('.vigilante-totp-reset-results').removeClass('active').empty();
            this.toggleResetButton();
        },

        getExcludedUserIds: function() {
            var ids = [];
            $('.vigilante-2fa-excluded-user').each(function() { ids.push($(this).data('user-id')); });
            return ids;
        },

        toggleResetButton: function() {
            $('#vigilante_totp_reset_btn').toggle($('.vigilante-totp-reset-user').length > 0);
        },

        resetTotpUsers: function($btn) {
            var self = this;
            var ids = [];
            $('.vigilante-totp-reset-user').each(function() { ids.push($(this).data('user-id')); });
            if (!ids.length) return;

            $btn.prop('disabled', true).text('Resetting...');
            var $status = $('.vigilante-totp-reset-status');

            $.post(self.ajaxUrl(), {
                action: 'vigilante_reset_totp_users',
                nonce: self.nonce(),
                user_ids: ids
            }, function(response) {
                $btn.prop('disabled', false).text('Reset selected');
                if (response.success) {
                    $status.addClass('success').text(response.data.message);
                    $('.vigilante-totp-reset-selected').empty();
                    self.toggleResetButton();
                } else {
                    $status.addClass('error').text(response.data || 'Error');
                }
                setTimeout(function() { $status.removeClass('success error').text(''); }, 4000);
            });
        },

        sendNotification: function($btn) {
            var self = this;
            var $status = $btn.siblings('.vigilante-2fa-notification-status');
            var mode = $('input[name="vigilante_2fa_notify_mode"]:checked').val() || 'all';

            $btn.prop('disabled', true).text(self.str('sending'));
            $status.removeClass('success error').text('');

            $.post(self.ajaxUrl(), {
                action: 'vigilante_send_2fa_notification',
                nonce: self.nonce(),
                mode: mode
            }, function(response) {
                $btn.prop('disabled', false).text(self.str('sendNotification'));
                if (response.success) {
                    var msg = response.data.sent + ' ' + self.str('notificationsSent');
                    if (response.data.skipped > 0) msg += ', ' + response.data.skipped + ' ' + self.str('skipped');
                    if (response.data.failed > 0) msg += ', ' + response.data.failed + ' ' + self.str('failed');
                    $status.addClass('success').text(msg);
                } else {
                    $status.addClass('error').text(response.data || 'Error');
                }
            });
        },

        // Helpers
        ajaxUrl: function() { return typeof vigilanteAdmin !== 'undefined' ? vigilanteAdmin.ajaxUrl : ajaxurl; },
        nonce: function() { return typeof vigilanteAdmin !== 'undefined' ? vigilanteAdmin.nonce : ''; },
        str: function(key) {
            if (typeof vigilanteAdmin !== 'undefined' && vigilanteAdmin.strings && vigilanteAdmin.strings[key]) return vigilanteAdmin.strings[key];
            var fallback = { searching: 'Searching...', noUsersFound: 'No users found', sending: 'Sending...', sendNotification: 'Send notification now', notificationsSent: 'sent', skipped: 'skipped', failed: 'failed' };
            return fallback[key] || key;
        },
        esc: function(text) {
            var map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
            return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
        }
    };

    // =========================================================================
    // TOTP profile setup module (user profile page)
    // =========================================================================
    var VigilanteTOTPProfile = {
        init: function() {
            if (!$('.vigilante-totp-profile').length) return;
            this.bindEvents();
        },

        bindEvents: function() {
            var self = this;
            $(document).on('click', '.vigilante-totp-start-setup', function() { self.startSetup(); });
            $(document).on('click', '.vigilante-totp-confirm-setup', function() { self.confirmSetup(); });
            $(document).on('click', '.vigilante-totp-regenerate-backup', function() { self.regenerateBackup($(this)); });
            $(document).on('click', '.vigilante-totp-reconfigure', function() { self.reconfigure($(this)); });
            $(document).on('keypress', '#vigilante_totp_verify_code', function(e) {
                if (e.which === 13) { e.preventDefault(); $('.vigilante-totp-confirm-setup').click(); }
            });
        },

        cfg: function() {
            return typeof vigilanteTOTP !== 'undefined' ? vigilanteTOTP : { ajaxUrl: ajaxurl, nonce: '', strings: {} };
        },

        getUserId: function() {
            // Our own hidden field (most reliable)
            var uid = $('.vigilante-totp-user-id').val();
            if (uid && parseInt(uid, 10) > 0) return parseInt(uid, 10);
            // WordPress profile hidden fields
            uid = $('input[name="checkuser_id"]').val() || $('input[name="user_id"]').val();
            if (uid && parseInt(uid, 10) > 0) return parseInt(uid, 10);
            // URL param (edit other user)
            var m = window.location.search.match(/user_id=(\d+)/);
            if (m) return parseInt(m[1], 10);
            // Fallback: server will use current user
            return 0;
        },

        startSetup: function() {
            var self = this;
            var c = this.cfg();
            var $btn = $('.vigilante-totp-start-setup');
            $btn.prop('disabled', true).text(c.strings.generating || 'Generating...');

            $.post(c.ajaxUrl, {
                action: 'vigilante_totp_get_setup',
                nonce: c.nonce,
                user_id: self.getUserId()
            }, function(response) {
                if (response.success) {
                    var d = response.data;
                    $('.vigilante-totp-setup-loading').hide();

                    // Generate QR code client-side
                    var $qrContainer = $('.vigilante-totp-qr-container');
                    $qrContainer.empty();
                    var qrEl = document.createElement('div');
                    $qrContainer.append(qrEl);

                    if (typeof QRCode !== 'undefined') {
                        new QRCode(qrEl, {
                            text: d.uri,
                            width: 200,
                            height: 200,
                            colorDark: '#000000',
                            colorLight: '#ffffff',
                            correctLevel: QRCode.CorrectLevel.M
                        });
                    } else {
                        $qrContainer.html('<p style="color:#d63638;">QR library not loaded. Use the manual key below.</p>');
                    }

                    // Format secret in groups of 4 for readability
                    var formattedSecret = d.secret.replace(/(.{4})/g, '$1 ').trim();
                    $('.vigilante-totp-secret-display').text(formattedSecret);
                    $('.vigilante-totp-setup-qr').data('secret', d.secret).show();
                    $('#vigilante_totp_verify_code').focus();
                } else {
                    $btn.prop('disabled', false).text('Start setup');
                    alert(response.data || 'Error');
                }
            });
        },

        confirmSetup: function() {
            var self = this;
            var c = this.cfg();
            var code = $('#vigilante_totp_verify_code').val().trim();
            var secret = $('.vigilante-totp-setup-qr').data('secret');
            var $status = $('.vigilante-totp-setup-status');
            var $btn = $('.vigilante-totp-confirm-setup');

            if (!code || code.length !== 6) {
                $status.text('Enter a valid 6-digit code.').addClass('error');
                return;
            }

            $btn.prop('disabled', true);
            $status.text(c.strings.verifying || 'Verifying...').removeClass('error success');

            $.post(c.ajaxUrl, {
                action: 'vigilante_totp_verify_setup',
                nonce: c.nonce,
                user_id: self.getUserId(),
                code: code,
                secret: secret
            }, function(response) {
                if (response.success) {
                    $status.text('').removeClass('error');
                    $('.vigilante-totp-setup-qr').hide();
                    var $success = $('.vigilante-totp-setup-success');
                    if (response.data.backup_codes) {
                        self.renderCodes(response.data.backup_codes, $success.find('.vigilante-totp-backup-codes-display'));
                    }
                    $success.show();
                } else {
                    $btn.prop('disabled', false);
                    $status.text(response.data || 'Invalid code.').addClass('error');
                }
            });
        },

        regenerateBackup: function($btn) {
            var self = this;
            var c = this.cfg();
            if (!confirm(c.strings.confirmRegen || 'This will invalidate all existing backup codes. Continue?')) return;

            $btn.prop('disabled', true);
            $.post(c.ajaxUrl, {
                action: 'vigilante_totp_regenerate_backup',
                nonce: c.nonce,
                user_id: $btn.data('user')
            }, function(response) {
                $btn.prop('disabled', false);
                if (response.success && response.data.backup_codes) {
                    var $container = $btn.closest('td').find('.vigilante-totp-backup-codes-display');
                    self.renderCodes(response.data.backup_codes, $container);
                }
            });
        },

        reconfigure: function($btn) {
            var c = this.cfg();

            if (!confirm(c.strings.confirmReconfig || 'This will reset your current TOTP setup. Continue?')) return;

            $btn.prop('disabled', true).text('Resetting...');

            $.post(c.ajaxUrl, {
                action: 'vigilante_totp_reconfigure',
                nonce: c.nonce,
                user_id: $btn.data('user')
            }, function(response) {
                if (response.success) {
                    window.location.reload();
                } else {
                    $btn.prop('disabled', false).text($btn.data('original-text') || 'Set up new authenticator');
                    alert(response.data || 'Error');
                }
            }).fail(function() {
                $btn.prop('disabled', false);
            });
        },

        renderCodes: function(codes, $container) {
            var c = this.cfg();
            var html = '<div class="vigilante-totp-backup-codes-box">';
            html += '<p class="vigilante-totp-backup-warning"><span class="dashicons dashicons-warning"></span> ';
            html += (c.strings.saveBackupCodes || 'Save these backup codes now. They will not be shown again.');
            html += '</p><div class="vigilante-totp-codes-grid">';
            $.each(codes, function(i, code) {
                html += '<code>' + (i + 1) + '. ' + code + '</code>';
            });
            html += '</div></div>';
            $container.html(html).show();
        }
    };

    // =========================================================================
    // Password expiration: per-user exclusion search
    // Same UX as the 2FA exclusion picker, reusing the existing CSS classes.
    // =========================================================================
    var VigilantePwExpExclusion = {
        searchTimeout: null,
        minSearchLength: 2,

        init: function() {
            if (!$('#vigilante_pwexp_user_search').length) return;
            this.bindEvents();
        },

        bindEvents: function() {
            var self = this;

            $(document).on('input', '#vigilante_pwexp_user_search', function() {
                self.handleSearch($(this));
            });
            $(document).on('focus', '#vigilante_pwexp_user_search', function() {
                var $r = $(this).siblings('.vigilante-pwexp-search-results');
                if ($r.children().length > 0) $r.addClass('active');
            });
            $(document).on('click', '.vigilante-pwexp-search-results .search-result-item', function() {
                self.addExcludedUser($(this));
            });
            $(document).on('click', '.vigilante-pwexp-excluded-user .remove-user', function() {
                $(this).closest('.vigilante-pwexp-excluded-user').remove();
            });
            $(document).on('click', function(e) {
                if (!$(e.target).closest('#vigilante_pwexp_user_search').length &&
                    !$(e.target).closest('.vigilante-pwexp-search-results').length) {
                    $('.vigilante-pwexp-search-results').removeClass('active');
                }
            });
        },

        handleSearch: function($input) {
            var self = this;
            var query = $input.val().trim();
            var $results = $input.siblings('.vigilante-pwexp-search-results');

            if (this.searchTimeout) clearTimeout(this.searchTimeout);
            if (query.length < this.minSearchLength) {
                $results.removeClass('active').empty();
                return;
            }

            $results.addClass('active').html('<div class="searching">' + Vigilante2FA.str('searching') + '</div>');

            this.searchTimeout = setTimeout(function() {
                $.post(Vigilante2FA.ajaxUrl(), {
                    action: 'vigilante_search_users_password_reset',
                    nonce: Vigilante2FA.nonce(),
                    query: query
                }, function(response) {
                    if (response.success && response.data.length > 0) {
                        Vigilante2FA.renderResults(response.data, $results);
                    } else {
                        $results.html('<div class="no-results">' + Vigilante2FA.str('noUsersFound') + '</div>');
                    }
                });
            }, 300);
        },

        addExcludedUser: function($item) {
            var uid = $item.data('user-id');
            if ($('.vigilante-pwexp-excluded-user[data-user-id="' + uid + '"]').length) return;

            $('.vigilante-pwexp-excluded-users').append(
                '<div class="vigilante-pwexp-excluded-user" data-user-id="' + uid + '">' +
                '<span class="user-display">' + Vigilante2FA.esc($item.data('user-display')) + ' (' + Vigilante2FA.esc($item.data('user-email')) + ')</span>' +
                '<button type="button" class="remove-user" aria-label="Remove">&times;</button>' +
                '<input type="hidden" name="user_security[password_expiration][excluded_users][]" value="' + uid + '">' +
                '</div>'
            );
            $('#vigilante_pwexp_user_search').val('');
            $('.vigilante-pwexp-search-results').removeClass('active').empty();
        }
    };

    $(document).ready(function() {
        Vigilante2FA.init();
        VigilanteTOTPProfile.init();
        VigilantePwExpExclusion.init();
    });

})(jQuery);