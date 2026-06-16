/**
 * Vigilante Admin JavaScript
 *
 * @package Vigilante
 */

(function($) {
    'use strict';

    var Vigilante_Admin = {

        /**
         * Initialize
         */
        init: function() {
            this.bindEvents();
            this.initModuleToggles();
            this.initFileIntegrityPagination();

            // Activity log pagination state
            this.logPage = 1;
            this.logPerPage = 20;
            this.logSearchTimer = null;
        },

        /**
         * Bind events
         */
        bindEvents: function() {
            // Save settings forms
            $(document).on('submit', '.vigilante-settings-form', this.handleFormSubmit.bind(this));

            // Module toggles in dashboard
            $(document).on('change', '.vigilante-module-item input[type="checkbox"]', this.handleModuleToggle.bind(this));

            // Apply preset
            $(document).on('click', '.vigilante-preset-btn', this.handleApplyPreset.bind(this));

            // Reset section to defaults
            $(document).on('click', '.vigilante-reset-section-btn', this.handleResetSection.bind(this));

            // Clear lockouts
            $(document).on('click', '.vigilante-clear-lockout', this.handleClearLockout.bind(this));
            $(document).on('click', '.vigilante-clear-all-lockouts', this.handleClearAllLockouts.bind(this));

            // Unblock firewall rate-limited IPs
            $(document).on('click', '.vigilante-unblock-firewall-ip', this.handleUnblockFirewallIp.bind(this));

            // Clear logs
            $(document).on('click', '.vigilante-clear-logs', this.handleClearLogs.bind(this));

            // Run scan
            $(document).on('click', '.vigilante-run-scan', this.handleRunScan.bind(this));
            $(document).on('click', '.vigilante-ignore-file', this.handleIgnoreFile.bind(this));
            $(document).on('click', '.vigilante-unignore-file', this.handleUnignoreFile.bind(this));
            $(document).on('click', '.vigilante-clear-ignored', this.handleClearIgnored.bind(this));

            // Closed plugins ignore controls (separate slug-based list, not file paths).
            $(document).on('click', '.vigilante-ignore-closed-plugin', this.handleIgnoreClosedPlugin.bind(this));
            $(document).on('click', '.vigilante-unignore-closed-plugin', this.handleUnignoreClosedPlugin.bind(this));
            $(document).on('click', '.vigilante-clear-ignored-closed-plugins', this.handleClearIgnoredClosedPlugins.bind(this));

            // Bulk selection inside file integrity tables
            $(document).on('change', '.vigilante-fi-cb-all', this.handleFiSelectAll.bind(this));
            $(document).on('change', '.vigilante-fi-cb', this.handleFiCheckboxChange.bind(this));
            $(document).on('click', '.vigilante-bulk-ignore', this.handleBulkIgnore.bind(this));
            $(document).on('click', '.vigilante-bulk-unignore', this.handleBulkUnignore.bind(this));

            // Clear scan results
            $(document).on('click', '.vigilante-clear-scan', this.handleClearScan.bind(this));

            // Critical config file actions
            $(document).on('click', '.vigilante-approve-critical-file', this.handleApproveCriticalFile.bind(this));
            $(document).on('click', '.vigilante-toggle-critical-content', this.handleToggleCriticalContent.bind(this));

            // Export/Import settings
            $(document).on('click', '.vigilante-export-settings', this.handleExportSettings.bind(this));
            $(document).on('click', '.vigilante-import-settings', this.handleImportSettings.bind(this));
            $(document).on('change', '#vigilante-import-file', this.handleImportFile.bind(this));

            // Reset settings
            $(document).on('click', '.vigilante-reset-settings', this.handleResetSettings.bind(this));

            // Test headers
            $(document).on('click', '.vigilante-test-headers', this.handleTestHeaders.bind(this));

            // Login URL notification
            $(document).on('click', '#vigilante_notify_login_url', this.handleNotifyLoginUrl.bind(this));
            $(document).on('input', '#vigilante_custom_login_url', this.handleLoginUrlToggle.bind(this));

            // Activity log filters
            $(document).on('change', '#vigilante-log-type-filter, #vigilante-log-severity-filter, #vigilante-log-method-filter', this.handleLogFilter.bind(this));
            $(document).on('click', '#vigilante-log-refresh', this.handleLogFilter.bind(this));

            // Activity log search (debounced, min 3 chars)
            $(document).on('input', '#vigilante-log-search', this.handleLogSearch.bind(this));

            // Activity log pagination
            $(document).on('click', '#vigilante-log-pagination .vigilante-page-first', function() { Vigilante_Admin.goToLogPage('first'); });
            $(document).on('click', '#vigilante-log-pagination .vigilante-page-prev', function() { Vigilante_Admin.goToLogPage('prev'); });
            $(document).on('click', '#vigilante-log-pagination .vigilante-page-next', function() { Vigilante_Admin.goToLogPage('next'); });
            $(document).on('click', '#vigilante-log-pagination .vigilante-page-last', function() { Vigilante_Admin.goToLogPage('last'); });

            // File integrity client-side pagination
            $(document).on('click', '.vigilante-fi-pagination .vigilante-page-first', function() { Vigilante_Admin.goToFilePage($(this).closest('.vigilante-paginated-section'), 'first'); });
            $(document).on('click', '.vigilante-fi-pagination .vigilante-page-prev', function() { Vigilante_Admin.goToFilePage($(this).closest('.vigilante-paginated-section'), 'prev'); });
            $(document).on('click', '.vigilante-fi-pagination .vigilante-page-next', function() { Vigilante_Admin.goToFilePage($(this).closest('.vigilante-paginated-section'), 'next'); });
            $(document).on('click', '.vigilante-fi-pagination .vigilante-page-last', function() { Vigilante_Admin.goToFilePage($(this).closest('.vigilante-paginated-section'), 'last'); });

            // Export logs
            $(document).on('click', '.vigilante-export-logs', this.handleExportLogs.bind(this));

            // Create backup
            $(document).on('click', '.vigilante-create-backup', this.handleCreateBackup.bind(this));

            // View log details modal
            $(document).on('click', '.vigilante-view-log-details', this.handleViewLogDetails.bind(this));
            $(document).on('click', '.vigilante-modal-close, .vigilante-modal', this.handleCloseModal.bind(this));
            $(document).on('click', '.vigilante-add-to-list', this.handleAddToFirewallList.bind(this));
            $(document).on('click', '.vigilante-modal-content', function(e) {
                e.stopPropagation();
            });

            // Under Attack mode
            $(document).on('click', '.vigilante-ua-activate', this.handleUnderAttackActivate.bind(this));
            $(document).on('click', '.vigilante-ua-deactivate', this.handleUnderAttackDeactivate.bind(this));

            // Database backup
            $(document).on('click', '.vigilante-db-backup-toggle', this.handleDbBackupToggle.bind(this));
            $(document).on('click', '.vigilante-db-backup-download', this.handleDbBackupDownload.bind(this));
            $(document).on('change', '#vigilante-db-select-all', this.handleDbSelectAll.bind(this));
            $(document).on('change', '.vigilante-db-table-check', this.handleDbTableCheck.bind(this));

            // Database prefix
            $(document).on('click', '.vigilante-db-regenerate-prefix', this.handleDbRegeneratePrefix.bind(this));
            $(document).on('change', '#vigilante-prefix-backup-confirm', this.handleDbPrefixConfirmToggle.bind(this));
            $(document).on('click', '.vigilante-db-change-prefix', this.handleDbChangePrefix.bind(this));

            // Settings search
            $(document).on('input', '#vigilante-settings-search', this.handleSettingsSearch.bind(this));
            $(document).on('focus', '#vigilante-settings-search', this.handleSettingsSearch.bind(this));
            $(document).on('keydown', '#vigilante-settings-search', this.handleSettingsSearchKey.bind(this));
            $(document).on('mouseenter', '.vigilante-search-item', this.handleSettingsSearchHover.bind(this));
            $(document).on('click', function(e) {
                if (!$(e.target).closest('.vigilante-search-wrapper').length) {
                    $('#vigilante-settings-search-results').attr('hidden', true);
                }
            });
            // Global "/" shortcut to focus search
            $(document).on('keydown', function(e) {
                if (e.key !== '/') return;
                var $t = $(e.target);
                if ($t.is('input, textarea, select') || $t.is('[contenteditable="true"]')) return;
                var $search = $('#vigilante-settings-search');
                if (!$search.length) return;
                e.preventDefault();
                $search.focus().select();
            });

            // Start Under Attack countdown if active
            this.initUnderAttackCountdown();
        },

        /**
         * Initialize module toggles
         */
        initModuleToggles: function() {
            $(document).on('change', '.vigilante-module-item input[type="checkbox"]', function() {
                var $item = $(this).closest('.vigilante-module-item');
                var module = $(this).data('module');
                var enabled = $(this).is(':checked');

                $item.toggleClass('enabled', enabled).toggleClass('disabled', !enabled);

                // Save module state
                Vigilante_Admin.saveModuleState(module, enabled);
            });
        },

        /**
         * Save module state
         */
        saveModuleState: function(module, enabled) {
            var $item = $('.vigilante-module-item input[data-module="' + module + '"]').closest('.vigilante-module-item');
            
            // Show saving state
            $item.addClass('vigilante-saving');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_save_settings',
                    nonce: vigilanteAdmin.nonce,
                    section: 'modules',
                    data: 'modules[' + module + ']=' + (enabled ? '1' : '0')
                },
                success: function(response) {
                    if (response.success) {
                        $item.removeClass('vigilante-saving').addClass('vigilante-saved');
                        // Show success then reload to update recommendations and all UI
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.saved);
                        setTimeout(function() {
                            location.reload();
                        }, 800);
                    } else {
                        $item.removeClass('vigilante-saving');
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.error);
                    }
                },
                error: function() {
                    $item.removeClass('vigilante-saving');
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                }
            });
        },

        /**
         * Update security score after module toggle
         */
        updateSecurityScore: function() {
            var total = $('.vigilante-module-item').length;
            var enabled = $('.vigilante-module-item.enabled').length;
            var score = total > 0 ? Math.round((enabled / total) * 100) : 0;
            
            // Grade thresholds: A (90+), B (70-89), C (50-69), D (30-49), E (0-29)
            var grade;
            if (score >= 90) {
                grade = 'A';
            } else if (score >= 70) {
                grade = 'B';
            } else if (score >= 50) {
                grade = 'C';
            } else if (score >= 30) {
                grade = 'D';
            } else {
                grade = 'E';
            }
            
            // Update score display
            $('.vigilante-score-text').text(score + '%');
            $('.vigilante-grade').text(grade);
            $('.vigilante-score-circle').removeClass('vigilante-grade-a vigilante-grade-b vigilante-grade-c vigilante-grade-d vigilante-grade-e')
                                  .addClass('vigilante-grade-' + grade.toLowerCase());
            
            // Update modules count text - use fixed string to prevent text accumulation
            var $countText = $('.vigilante-security-score p');
            if ($countText.length) {
                var modulesText = (vigilanteAdmin.strings.modulesEnabled || '%1$d / %2$d modules enabled').replace('%1$d', enabled).replace('%2$d', total);
                $countText.text(modulesText);
            }
        },

        /**
         * Update configuration status badge
         */
        updateConfigBadge: function(preset) {
            var $badge = $('.vigilante-config-status .vigilante-preset-badge');
            if ($badge.length) {
                $badge.removeClass('vigilante-preset-standard vigilante-preset-maximum vigilante-preset-custom vigilante-preset-under-attack');
                
                if (vigilanteAdmin.underAttack && vigilanteAdmin.underAttack.active) {
                    $badge.addClass('vigilante-preset-under-attack').text(vigilanteAdmin.strings.underAttackLabel || 'Under Attack');
                } else if (preset === 'standard') {
                    $badge.addClass('vigilante-preset-standard').text(vigilanteAdmin.strings.standardLabel || 'Standard');
                } else if (preset === 'maximum') {
                    $badge.addClass('vigilante-preset-maximum').text(vigilanteAdmin.strings.maximumLabel || 'Maximum Security');
                } else {
                    $badge.addClass('vigilante-preset-custom').text(vigilanteAdmin.strings.customConfig || 'Custom Configuration');
                }
            }
        },

        /**
         * Handle form submit
         */
        handleFormSubmit: function(e) {
            e.preventDefault();

            var $form = $(e.currentTarget);
            var $btn = $form.find('.vigilante-save-btn');
            var section = $form.data('section');

            $btn.prop('disabled', true).text(vigilanteAdmin.strings.saving);
            $form.addClass('vigilante-loading');

            // Build form data including unchecked checkboxes
            var formData = Vigilante_Admin.serializeFormWithCheckboxes($form);

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_save_settings',
                    nonce: vigilanteAdmin.nonce,
                    section: section,
                    data: formData
                },
                success: function(response) {
                    if (response.success) {
                        var msg = response.data && response.data.message ? response.data.message : (response.data || vigilanteAdmin.strings.saved);
                        Vigilante_Admin.showNotice('success', msg);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.error);
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                },
                complete: function() {
                    $btn.prop('disabled', false).text($btn.data('original-text') || vigilanteAdmin.strings.saved);
                    $form.removeClass('vigilante-loading');

                    // Reset button text after delay
                    setTimeout(function() {
                        $btn.text($btn.data('original-text') || vigilanteAdmin.strings.saveSettings || 'Save Settings');
                    }, 2000);
                }
            });
        },

        /**
         * Handle module toggle in dashboard
         */
        handleModuleToggle: function(e) {
            var $checkbox = $(e.currentTarget);
            var module = $checkbox.data('module');
            var enabled = $checkbox.is(':checked');
            var $item = $checkbox.closest('.vigilante-module-item');

            // Visual feedback
            $item.addClass('vigilante-loading');

            // Build data for modules section
            var formData = 'modules[' + module + ']=' + (enabled ? '1' : '0');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_save_settings',
                    nonce: vigilanteAdmin.nonce,
                    section: 'modules',
                    data: formData
                },
                success: function(response) {
                    if (response.success) {
                        // Update visual state
                        if (enabled) {
                            $item.removeClass('disabled').addClass('enabled');
                        } else {
                            $item.removeClass('enabled').addClass('disabled');
                        }
                        Vigilante_Admin.updateSecurityScore();
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.saved);
                        
                        // Update config badge to Custom (since settings were manually changed)
                        Vigilante_Admin.updateConfigBadge('custom');
                        
                        // Clear active preset indicator
                        $('.vigilante-preset-card').removeClass('vigilante-preset-active');
                        $('.vigilante-active-indicator').remove();
                    } else {
                        // Revert checkbox on error
                        $checkbox.prop('checked', !enabled);
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.error);
                    }
                },
                error: function() {
                    // Revert checkbox on error
                    $checkbox.prop('checked', !enabled);
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                },
                complete: function() {
                    $item.removeClass('vigilante-loading');
                }
            });
        },

        /**
         * Serialize form including unchecked checkboxes
         */
        serializeFormWithCheckboxes: function($form) {
            var data = $form.serializeArray();
            var checkboxNames = [];
            
            // Find all checkboxes and add unchecked ones with value 0
            $form.find('input[type="checkbox"]').each(function() {
                var name = $(this).attr('name');
                if (name && checkboxNames.indexOf(name) === -1) {
                    checkboxNames.push(name);
                    if (!$(this).is(':checked')) {
                        data.push({ name: name, value: '0' });
                    }
                }
            });
            
            // Convert to query string
            return $.param(data);
        },

        /**
         * Handle apply preset
         */
        handleApplyPreset: function(e) {
            e.preventDefault();

            var preset = $(e.currentTarget).data('preset');

            if (!confirm(vigilanteAdmin.strings.confirm + ' ' + (vigilanteAdmin.strings.confirmApplyPreset || 'Apply the "%s" preset?').replace('%s', preset))) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_apply_preset',
                    nonce: vigilanteAdmin.nonce,
                    preset: preset
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', response.data);
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                }
            });
        },

        /**
         * Handle Under Attack mode activation
         */
        handleUnderAttackActivate: function(e) {
            e.preventDefault();

            if (!confirm(vigilanteAdmin.strings.underAttackConfirmActivate)) {
                return;
            }

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.underAttackActivating);

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_activate_under_attack',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', response.data.message);
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.underAttackActivate || 'Activate for 4 hours');
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.underAttackActivate || 'Activate for 4 hours');
                }
            });
        },

        /**
         * Handle Under Attack mode deactivation
         */
        handleUnderAttackDeactivate: function(e) {
            e.preventDefault();

            if (!confirm(vigilanteAdmin.strings.underAttackConfirmDeactivate)) {
                return;
            }

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.underAttackDeactivating);

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_deactivate_under_attack',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', response.data);
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.deactivate || 'Deactivate');
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.deactivate || 'Deactivate');
                }
            });
        },

        /**
         * Initialize Under Attack countdown timer
         */
        initUnderAttackCountdown: function() {
            var $countdown = $('.vigilante-ua-countdown');
            if (!$countdown.length) {
                return;
            }

            var expiresAt = parseInt($countdown.data('expires'), 10);
            if (!expiresAt) {
                return;
            }

            var $timeEl = $countdown.find('.vigilante-ua-time');

            var updateCountdown = function() {
                var now = Math.floor(Date.now() / 1000);
                var remaining = expiresAt - now;

                if (remaining <= 0) {
                    location.reload();
                    return;
                }

                var hours = Math.floor(remaining / 3600);
                var mins = Math.floor((remaining % 3600) / 60);

                var text = vigilanteAdmin.strings.underAttackRemaining || '%1$dh %2$dm remaining';
                text = text.replace('%1$d', hours).replace('%2$d', mins);
                $timeEl.text(text);
            };

            // Run immediately, then update every minute
            updateCountdown();
            setInterval(updateCountdown, 60000);
        },

        /**
         * Handle reset section to defaults
         */
        handleResetSection: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var $form = $btn.closest('form');
            var section = $form.data('section');

            if (!section) {
                Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.couldNotDetermineSection || 'Could not determine section.');
                return;
            }

            if (!confirm(vigilanteAdmin.strings.confirmResetSection || 'Reset this section to default values? This cannot be undone.')) {
                return;
            }

            var originalText = $btn.data('original-text') || $btn.text();
            $btn.prop('disabled', true).html(vigilanteAdmin.strings.loading + ' <span class="vigilante-spinner"></span>');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_reset_section',
                    nonce: vigilanteAdmin.nonce,
                    section: section
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', response.data.message || vigilanteAdmin.strings.sectionResetDefaults || 'Section reset to defaults.');
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                },
                complete: function() {
                    $btn.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Handle clear single lockout
         */
        handleClearLockout: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var ip = $btn.data('ip');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_lockouts',
                    nonce: vigilanteAdmin.nonce,
                    ip: ip
                },
                success: function(response) {
                    if (response.success) {
                        var $container = $btn.closest('.vigilante-paginated-section');
                        $btn.closest('tr').fadeOut(function() {
                            $(this).remove();
                            Vigilante_Admin.refreshFilePagination($container);
                        });
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                }
            });
        },

        /**
         * Handle clear all lockouts
         */
        handleClearAllLockouts: function(e) {
            e.preventDefault();

            if (!confirm(vigilanteAdmin.strings.confirm)) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_lockouts',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                }
            });
        },

        /**
         * Handle clear logs
         */
        handleClearLogs: function(e) {
            e.preventDefault();

            if (!confirm(vigilanteAdmin.strings.confirm + ' ' + (vigilanteAdmin.strings.confirmClearLogs || 'This will delete all activity logs.'))) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_logs',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                }
            });
        },

        /**
         * Handle run scan
         */
        handleRunScan: function(e) {
            e.preventDefault();
            e.stopPropagation();

            var $btn = $(e.currentTarget);
            var $results = $('#vigilante-scan-results');
            var $lastResults = $('#vigilante-last-scan-results').closest('.vigilante-settings-section');

            // Hide previous results section
            $lastResults.hide();
            $results.empty().hide();

            $btn.prop('disabled', true).html(vigilanteAdmin.strings.scanning + ' <span class="vigilante-spinner"></span>');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                timeout: 120000,
                data: {
                    action: 'vigilante_run_scan',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Reload the page so the server-side render shows ALL findings
                        // in their canonical sections (Suspicious, Extra, Critical Config,
                        // Closed + Removed Plugins, Modified). The legacy in-place JS
                        // render only knows the file-level categories and would leave
                        // the Closed + Removed subsection hidden after a scan.
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.scanComplete);
                        setTimeout(function() { location.reload(); }, 600);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.scanFailed || 'Scan failed');
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.runScanNow || 'Run Scan Now');
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', (vigilanteAdmin.strings.scanError || 'Scan error: %s').replace('%s', error));
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.runScanNow || 'Run Scan Now');
                }
            });
        },

        /**
         * Handle clear scan results
         */
        handleClearScan: function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            if (!confirm(vigilanteAdmin.strings.confirmClearScan || 'Are you sure you want to clear all scan results?')) {
                return;
            }

            var $btn = $(e.currentTarget);
            var originalText = $btn.text();
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.clearing || 'Clearing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_scan',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        // Hide all scan results
                        $('#vigilante-scan-results').empty().hide();
                        $('#vigilante-last-scan-results').closest('.vigilante-settings-section').fadeOut();
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.scanResultsCleared || 'Scan results cleared. Page will reload...');
                        // Reload page to reflect changes
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.failedClearResults || 'Failed to clear results');
                        $btn.prop('disabled', false).text(originalText);
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', (vigilanteAdmin.strings.ajaxError || 'AJAX Error: %s').replace('%s', error));
                    $btn.prop('disabled', false).text(originalText);
                },
                complete: function() {
                    // Button text restored in success/error handlers
                }
            });
        },

        /**
         * Handle toggle critical file content viewer
         */
        handleToggleCriticalContent: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var targetId = $btn.data('target');
            var $content = $('#' + targetId);

            // Use toggle instead of slideUp/slideDown because target can be a TR
            // (animations on table rows are inconsistent across browsers)
            if ($content.is(':visible')) {
                $content.hide();
                $btn.text($btn.data('label-show'));
            } else {
                $content.show();
                $btn.text($btn.data('label-hide'));
            }
        },

        /**
         * Handle approve critical file button click
         */
        handleApproveCriticalFile: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var file = $btn.data('file');
            var strings = vigilanteAdmin.strings;
            var originalText = $btn.text();

            $btn.prop('disabled', true).text(strings.approving || 'Approving...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_approve_critical_file',
                    nonce: vigilanteAdmin.nonce,
                    file: file
                },
                success: function(response) {
                    if (response.success) {
                        // Remove the approved file row and its diff row from the table.
                        // The diff row carries an id derived from the file name (same as
                        // sanitize_html_class() on PHP side), so we target it directly
                        // instead of relying on adjacency in the DOM.
                        var $row = $btn.closest('tr');
                        var fileId = String(file).replace(/[^a-z0-9_-]/gi, '-');
                        $('#vigilante-critical-content-' + fileId).remove();
                        $row.fadeOut(300, function() {
                            $(this).remove();
                            // If no more critical config rows, remove the entire section
                            if ($('.vigilante-critical-config-files tbody tr').length === 0) {
                                $('.vigilante-critical-config-files').fadeOut(300, function() { $(this).remove(); });
                            }
                        });
                        Vigilante_Admin.showNotice('success', strings.criticalApproved || response.data.message);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || 'Failed to approve.');
                        $btn.prop('disabled', false).text(originalText);
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', (strings.ajaxError || 'AJAX Error: %s').replace('%s', error));
                    $btn.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Handle ignore file button click
         */
        handleIgnoreFile: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var file = $btn.data('file');
            var strings = vigilanteAdmin.strings;

            $btn.prop('disabled', true).text(strings.ignoring || 'Ignoring...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_ignore_file',
                    nonce: vigilanteAdmin.nonce,
                    file: file
                },
                success: function(response) {
                    if (response.success) {
                        var $container = $btn.closest('.vigilante-paginated-section');
                        // Remove the row from the table
                        $btn.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                            // Refresh pagination after row removal
                            Vigilante_Admin.refreshFilePagination($container);
                        });
                        Vigilante_Admin.showNotice('success', strings.fileIgnored || 'File added to ignored list.');
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || 'Failed to ignore file');
                        $btn.prop('disabled', false).text(strings.ignore || 'Ignore');
                    }
                },
                error: function() {
                    $btn.prop('disabled', false).text(strings.ignore || 'Ignore');
                }
            });
        },

        /**
         * Handle stop ignoring file
         */
        handleUnignoreFile: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var file = $btn.data('file');
            var strings = vigilanteAdmin.strings;

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_unignore_file',
                    nonce: vigilanteAdmin.nonce,
                    file: file
                },
                success: function(response) {
                    if (response.success) {
                        var $container = $btn.closest('.vigilante-paginated-section');
                        $btn.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                            Vigilante_Admin.refreshFilePagination($container);
                        });
                        Vigilante_Admin.showNotice('success', strings.fileUnignored || 'File removed from ignored list.');
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || 'Failed');
                    }
                }
            });
        },

        /**
         * Handle clear all ignored files
         */
        handleClearIgnored: function(e) {
            e.preventDefault();
            var strings = vigilanteAdmin.strings;

            if (!confirm(strings.confirmClearIgnored || 'Remove all files from the ignored list?')) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_ignored',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', strings.ignoredCleared || 'Ignored files list cleared. Page will reload...');
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    }
                }
            });
        },

        /**
         * Ignore a closed/removed plugin slug. Reloads to refresh the section.
         */
        handleIgnoreClosedPlugin: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var slug = $btn.data('slug');
            var strings = vigilanteAdmin.strings || {};

            $btn.prop('disabled', true).text(strings.ignoring || 'Ignoring…');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_ignore_closed_plugin',
                    nonce: vigilanteAdmin.nonce,
                    slug: slug
                },
                success: function(response) {
                    if (response && response.success) {
                        Vigilante_Admin.showNotice('success', (response.data) || 'Plugin ignored.');
                        setTimeout(function() { location.reload(); }, 600);
                    } else {
                        Vigilante_Admin.showNotice('error', (response && response.data) || 'Failed.');
                        $btn.prop('disabled', false).text(strings.ignore || 'Ignore');
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', (strings.ajaxError || 'AJAX Error: %s').replace('%s', error));
                    $btn.prop('disabled', false).text(strings.ignore || 'Ignore');
                }
            });
        },

        /**
         * Stop ignoring a closed/removed plugin slug.
         */
        handleUnignoreClosedPlugin: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var slug = $btn.data('slug');
            var strings = vigilanteAdmin.strings || {};

            $btn.prop('disabled', true).text(strings.unignoring || 'Restoring…');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_unignore_closed_plugin',
                    nonce: vigilanteAdmin.nonce,
                    slug: slug
                },
                success: function(response) {
                    if (response && response.success) {
                        Vigilante_Admin.showNotice('success', (response.data) || 'Plugin restored to the active list.');
                        setTimeout(function() { location.reload(); }, 600);
                    } else {
                        Vigilante_Admin.showNotice('error', (response && response.data) || 'Failed.');
                        $btn.prop('disabled', false).text(strings.stopIgnoring || 'Stop ignoring');
                    }
                },
                error: function(xhr, status, error) {
                    Vigilante_Admin.showNotice('error', (strings.ajaxError || 'AJAX Error: %s').replace('%s', error));
                    $btn.prop('disabled', false).text(strings.stopIgnoring || 'Stop ignoring');
                }
            });
        },

        /**
         * Clear the entire ignored closed plugins list.
         */
        handleClearIgnoredClosedPlugins: function(e) {
            e.preventDefault();
            var strings = vigilanteAdmin.strings || {};

            if (!confirm(strings.confirmClearIgnoredClosedPlugins || 'Remove all plugins from the ignored closed plugins list? They will reappear in the main list and in email alerts.')) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_clear_ignored_closed_plugins',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response && response.success) {
                        Vigilante_Admin.showNotice('success', (response.data) || 'Ignored closed plugins list cleared.');
                        setTimeout(function() { location.reload(); }, 1000);
                    }
                }
            });
        },

        /**
         * Toggle all checkboxes inside a file integrity table when the
         * header "select all" checkbox changes. Only operates on visible
         * rows so it plays nice with client-side pagination.
         */
        handleFiSelectAll: function(e) {
            var $cb = $(e.currentTarget);
            var $section = $cb.closest('.vigilante-paginated-section');
            $section.find('table.vigilante-fi-paginated tbody tr:visible .vigilante-fi-cb').prop('checked', $cb.prop('checked'));
            this.refreshBulkBar($section);
        },

        /**
         * Refresh bulk bar state after individual checkbox change.
         */
        handleFiCheckboxChange: function(e) {
            var $section = $(e.currentTarget).closest('.vigilante-paginated-section');
            this.refreshBulkBar($section);

            // Sync the header "select all" with the current visible state
            var $allCb = $section.find('.vigilante-fi-cb-all');
            var $visible = $section.find('table.vigilante-fi-paginated tbody tr:visible .vigilante-fi-cb');
            var $checked = $visible.filter(':checked');
            $allCb.prop('checked', $visible.length > 0 && $checked.length === $visible.length);
        },

        /**
         * Update the count label and enable/disable the bulk action button.
         */
        refreshBulkBar: function($section) {
            var strings = vigilanteAdmin.strings;
            var mode = $section.data('bulk-mode'); // 'ignore' or 'unignore'
            var $checked = $section.find('.vigilante-fi-cb:checked');
            var count = $checked.length;
            var $btn = $section.find(mode === 'unignore' ? '.vigilante-bulk-unignore' : '.vigilante-bulk-ignore');
            var $count = $section.find('.vigilante-fi-bulk-count');

            $btn.prop('disabled', count === 0);

            if (count === 0) {
                $count.text('');
            } else {
                var template = (strings.bulkSelectedCount || '%d selected');
                $count.text(template.replace('%d', count));
            }
        },

        /**
         * Collect the file paths checked inside a section.
         */
        collectSelectedFiles: function($section) {
            var files = [];
            $section.find('.vigilante-fi-cb:checked').each(function() {
                var v = $(this).val();
                if (v) {
                    files.push(v);
                }
            });
            return files;
        },

        /**
         * Bulk add to ignored list.
         */
        handleBulkIgnore: function(e) {
            e.preventDefault();
            var self = this;
            var strings = vigilanteAdmin.strings;
            var $btn = $(e.currentTarget);
            var $section = $btn.closest('.vigilante-paginated-section');
            var files = this.collectSelectedFiles($section);

            if (files.length === 0) {
                Vigilante_Admin.showNotice('error', strings.bulkNoSelection || 'Select at least one file first.');
                return;
            }

            if (!confirm(strings.bulkConfirmIgnore || 'Ignore the selected files?')) {
                return;
            }

            var originalText = $btn.text();
            $btn.prop('disabled', true).text(strings.bulkProcessing || 'Processing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_bulk_ignore_files',
                    nonce: vigilanteAdmin.nonce,
                    files: files
                },
                success: function(response) {
                    if (response.success) {
                        // Remove processed rows from this section
                        files.forEach(function(file) {
                            $section.find('.vigilante-fi-cb').filter(function() {
                                return $(this).val() === file;
                            }).closest('tr').remove();
                        });
                        $section.find('.vigilante-fi-cb-all').prop('checked', false);
                        Vigilante_Admin.refreshFilePagination($section);
                        self.refreshBulkBar($section);
                        Vigilante_Admin.showNotice('success', (response.data && response.data.message) || strings.fileIgnored);
                    } else {
                        Vigilante_Admin.showNotice('error', (response.data && response.data.message) || response.data || 'Failed to ignore files');
                        $btn.prop('disabled', false).text(originalText);
                    }
                },
                error: function() {
                    $btn.prop('disabled', false).text(originalText);
                },
                // Restore the label on success too. refreshBulkBar() re-derives the
                // disabled state from the remaining selection but never rewrites the
                // button text, so without this the button stays on "Processing...".
                complete: function() {
                    $btn.text(originalText);
                }
            });
        },

        /**
         * Bulk remove from ignored list.
         */
        handleBulkUnignore: function(e) {
            e.preventDefault();
            var self = this;
            var strings = vigilanteAdmin.strings;
            var $btn = $(e.currentTarget);
            var $section = $btn.closest('.vigilante-paginated-section');
            var files = this.collectSelectedFiles($section);

            if (files.length === 0) {
                Vigilante_Admin.showNotice('error', strings.bulkNoSelection || 'Select at least one file first.');
                return;
            }

            if (!confirm(strings.bulkConfirmUnignore || 'Remove the selected files from ignored list?')) {
                return;
            }

            var originalText = $btn.text();
            $btn.prop('disabled', true).text(strings.bulkProcessing || 'Processing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_bulk_unignore_files',
                    nonce: vigilanteAdmin.nonce,
                    files: files
                },
                success: function(response) {
                    if (response.success) {
                        files.forEach(function(file) {
                            $section.find('.vigilante-fi-cb').filter(function() {
                                return $(this).val() === file;
                            }).closest('tr').remove();
                        });
                        $section.find('.vigilante-fi-cb-all').prop('checked', false);
                        Vigilante_Admin.refreshFilePagination($section);
                        self.refreshBulkBar($section);
                        Vigilante_Admin.showNotice('success', (response.data && response.data.message) || strings.fileUnignored);

                        // If the ignored table is now empty, hide its section.
                        if ($section.find('table.vigilante-fi-paginated tbody tr').length === 0) {
                            $('#vigilante-section-fi-ignored').fadeOut(300, function() { $(this).remove(); });
                        }
                    } else {
                        Vigilante_Admin.showNotice('error', (response.data && response.data.message) || response.data || 'Failed');
                        $btn.prop('disabled', false).text(originalText);
                    }
                },
                error: function() {
                    $btn.prop('disabled', false).text(originalText);
                },
                // Restore the label on success too. refreshBulkBar() re-derives the
                // disabled state from the remaining selection but never rewrites the
                // button text, so without this the button stays on "Processing...".
                complete: function() {
                    $btn.text(originalText);
                }
            });
        },

        /**
         * Display scan results
         */
        displayScanResults: function(results, $container, ignoredCount) {
            // Ensure arrays exist
            results.modified = results.modified || [];
            results.suspicious = results.suspicious || [];
            results.extra = results.extra || [];
            results.missing = results.missing || [];
            
            var strings = vigilanteAdmin.strings;
            
            var html = '<h2>' + strings.scanResults + '</h2>';
            html += '<div class="vigilante-scan-summary">';
            html += '<div class="vigilante-scan-stat vigilante-stat-ok">';
            html += '<span class="vigilante-stat-number">' + (results.ok || 0) + '</span>';
            html += '<span class="vigilante-stat-label">' + strings.ok + '</span>';
            html += '</div>';
            html += '<div class="vigilante-scan-stat vigilante-stat-modified">';
            html += '<span class="vigilante-stat-number">' + results.modified.length + '</span>';
            html += '<span class="vigilante-stat-label">' + strings.modified + '</span>';
            html += '</div>';
            html += '<div class="vigilante-scan-stat vigilante-stat-suspicious">';
            html += '<span class="vigilante-stat-number">' + results.suspicious.length + '</span>';
            html += '<span class="vigilante-stat-label">' + strings.suspicious + '</span>';
            html += '</div>';
            html += '<div class="vigilante-scan-stat vigilante-stat-extra">';
            html += '<span class="vigilante-stat-number">' + results.extra.length + '</span>';
            html += '<span class="vigilante-stat-label">' + (strings.extra || 'Extra') + '</span>';
            html += '</div>';
            if (ignoredCount > 0) {
                html += '<div class="vigilante-scan-stat vigilante-stat-ignored">';
                html += '<span class="vigilante-stat-number">' + ignoredCount + '</span>';
                html += '<span class="vigilante-stat-label">' + (strings.ignored || 'Ignored') + '</span>';
                html += '</div>';
            }
            html += '<div class="vigilante-scan-stat">';
            var computedTotal = (results.ok || 0) + results.modified.length + results.suspicious.length + results.extra.length + (ignoredCount || 0);
            html += '<span class="vigilante-stat-number">' + computedTotal + '</span>';
            html += '<span class="vigilante-stat-label">' + strings.totalScanned + '</span>';
            html += '</div>';
            html += '</div>';

            var bulkBar = '<div class="vigilante-fi-bulk-bar">'
                + '<button type="button" class="button vigilante-bulk-ignore" disabled>' + (strings.bulkIgnoreSelected || 'Ignore selected') + '</button>'
                + '<span class="vigilante-fi-bulk-count" aria-live="polite"></span>'
                + '</div>';
            var selectAllCell = '<td class="manage-column column-cb check-column"><input type="checkbox" class="vigilante-fi-cb-all" aria-label="' + (strings.selectAll || 'Select all') + '"></td>';

            // Suspicious files table
            if (results.suspicious.length > 0) {
                html += '<div class="vigilante-file-list vigilante-suspicious-files vigilante-paginated-section" data-bulk-mode="ignore">';
                html += '<h3 style="color: #d63638;">' + strings.suspiciousFiles + '</h3>';
                html += '<p class="description" style="color: #d63638;">' + strings.suspiciousWarning + '</p>';
                html += bulkBar;
                html += '<div class="vigilante-fi-pagination-wrap"></div>';
                html += '<table class="wp-list-table widefat fixed striped vigilante-fi-paginated">';
                html += '<thead><tr>' + selectAllCell + '<th>' + strings.file + '</th><th style="width: 250px;">' + strings.reason + '</th><th style="width: 120px;">' + strings.type + '</th><th style="width: 80px;">' + (strings.actions || 'Actions') + '</th></tr></thead>';
                html += '<tbody>';
                results.suspicious.forEach(function(file) {
                    html += '<tr>';
                    html += '<th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="' + file.file + '"></th>';
                    html += '<td><code style="color: #d63638;">' + file.file + '</code></td>';
                    html += '<td>' + (file.reason || strings.unknown) + '</td>';
                    html += '<td>' + (file.type || strings.unknown) + '</td>';
                    html += '<td><button type="button" class="button button-small vigilante-ignore-file" data-file="' + file.file + '">' + (strings.ignore || 'Ignore') + '</button></td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';
                html += '</div>';
            }

            // Extra files table
            if (results.extra.length > 0) {
                html += '<div class="vigilante-file-list vigilante-extra-files vigilante-paginated-section" data-bulk-mode="ignore">';
                html += '<h3 style="color: #b32d2e;">' + (strings.extraFiles || 'Extra Files') + '</h3>';
                html += '<p class="description">' + (strings.extraDescription || 'PHP files not in original distribution.') + '</p>';
                html += bulkBar;
                html += '<div class="vigilante-fi-pagination-wrap"></div>';
                html += '<table class="wp-list-table widefat fixed striped vigilante-fi-paginated">';
                html += '<thead><tr>' + selectAllCell + '<th>' + strings.file + '</th><th style="width: 250px;">' + strings.reason + '</th><th style="width: 120px;">' + strings.type + '</th><th style="width: 80px;">' + (strings.actions || 'Actions') + '</th></tr></thead>';
                html += '<tbody>';
                results.extra.forEach(function(file) {
                    html += '<tr>';
                    html += '<th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="' + file.file + '"></th>';
                    html += '<td><code style="color: #b32d2e;">' + file.file + '</code></td>';
                    html += '<td>' + (file.reason || strings.unknown) + '</td>';
                    html += '<td>' + (file.type || strings.unknown) + '</td>';
                    html += '<td><button type="button" class="button button-small vigilante-ignore-file" data-file="' + file.file + '">' + (strings.ignore || 'Ignore') + '</button></td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';
                html += '</div>';
            }

            // Split critical config from regular modified
            var criticalModified = [];
            var regularModified = [];
            results.modified.forEach(function(file) {
                if (file.type === 'critical_config') {
                    criticalModified.push(file);
                } else {
                    regularModified.push(file);
                }
            });

            // Critical config files section (same visual treatment as suspicious files)
            if (criticalModified.length > 0) {
                html += '<div class="vigilante-file-list vigilante-critical-config-files">';
                html += '<h3 style="color: #e36210;">' + (strings.criticalConfigTitle || 'Critical config files modified') + '</h3>';
                html += '<p class="description">' + (strings.criticalConfigDesc || '') + '</p>';
                html += '<table class="wp-list-table widefat fixed striped">';
                html += '<thead><tr><th>' + strings.file + '</th><th style="width: 200px;">' + (strings.changes || 'Changes') + '</th><th style="width: 220px;">' + (strings.actions || 'Actions') + '</th></tr></thead>';
                html += '<tbody>';

                var escHtml = function(s) { return $('<span>').text(s).html(); };

                criticalModified.forEach(function(file) {
                    var fileId = file.file.replace(/[^a-z0-9]/gi, '-');
                    var baselineSize = file.baseline_size ? Number(file.baseline_size).toLocaleString() : '?';
                    var currentSize = file.current_size ? Number(file.current_size).toLocaleString() : '?';
                    var diff = file.diff || {};
                    var added = diff.added || [];
                    var removed = diff.removed || [];
                    var diffUnavailable = !!diff.unavailable;

                    // Main row
                    html += '<tr>';
                    html += '<td><code style="color: #e36210;">' + file.file + '</code></td>';
                    html += '<td>';
                    if (!diffUnavailable) {
                        html += '<span style="color: #007017;">+' + added.length + '</span> <span style="color: #b32d2e;">-' + removed.length + '</span> ' + (strings.diffLines || 'lines') + '<br>';
                    }
                    html += '<small style="color: #50575e;">' + baselineSize + ' &rarr; ' + currentSize + ' bytes</small>';
                    html += '</td>';
                    html += '<td>';
                    html += '<button type="button" class="button button-small vigilante-toggle-critical-content" data-target="vigilante-critical-content-' + fileId + '" data-label-show="' + (strings.reviewChanges || 'Review changes') + '" data-label-hide="' + (strings.hideChanges || 'Hide changes') + '">' + (strings.reviewChanges || 'Review changes') + '</button> ';
                    html += '<button type="button" class="button button-small button-primary vigilante-approve-critical-file" data-file="' + file.file + '">' + (strings.approve || 'Approve') + '</button>';
                    html += '</td>';
                    html += '</tr>';

                    // Expandable diff row
                    html += '<tr id="vigilante-critical-content-' + fileId + '" class="vigilante-critical-content-row" style="display:none;">';
                    html += '<td colspan="3" style="padding: 0;">';
                    html += '<div class="vigilante-critical-content" style="max-height: 400px; overflow: auto; background: #fff; padding: 10px; font-size: 12px; line-height: 1.5; font-family: Consolas, Monaco, monospace; border-top: 1px solid #c3c4c7;">';
                    if (diffUnavailable) {
                        html += '<p style="color: #50575e; font-style: italic; margin: 0;">' + (strings.diffUnavailable || 'Diff not available.') + '</p>';
                    } else if (added.length === 0 && removed.length === 0) {
                        html += '<p style="color: #50575e; font-style: italic; margin: 0;">' + (strings.diffEmpty || 'No line changes detected.') + '</p>';
                    } else {
                        removed.forEach(function(rline) {
                            html += '<div style="background: #fbeaea; color: #b32d2e; padding: 1px 4px; white-space: pre-wrap; word-wrap: break-word;"><span style="display: inline-block; width: 50px; color: #999; user-select: none;">' + (rline.line || 0) + '</span>- ' + escHtml(rline.content || '') + '</div>';
                        });
                        added.forEach(function(aline) {
                            html += '<div style="background: #e6f4e9; color: #007017; padding: 1px 4px; white-space: pre-wrap; word-wrap: break-word;"><span style="display: inline-block; width: 50px; color: #999; user-select: none;">' + (aline.line || 0) + '</span>+ ' + escHtml(aline.content || '') + '</div>';
                        });
                    }
                    html += '</div>';
                    html += '</td>';
                    html += '</tr>';
                });

                html += '</tbody></table>';
                html += '</div>';
            }

            // Regular modified files table
            if (regularModified.length > 0) {
                html += '<div class="vigilante-file-list vigilante-paginated-section" data-bulk-mode="ignore">';
                html += '<h3>' + strings.modifiedFiles + '</h3>';
                html += '<p class="description">' + strings.modifiedDescription + '</p>';
                html += bulkBar;
                html += '<div class="vigilante-fi-pagination-wrap"></div>';
                html += '<table class="wp-list-table widefat fixed striped vigilante-fi-paginated">';
                html += '<thead><tr>' + selectAllCell + '<th>' + strings.file + '</th><th style="width: 100px;">' + strings.type + '</th><th style="width: 80px;">' + (strings.actions || 'Actions') + '</th></tr></thead>';
                html += '<tbody>';
                regularModified.forEach(function(file) {
                    html += '<tr>';
                    html += '<th scope="row" class="check-column"><input type="checkbox" class="vigilante-fi-cb" value="' + file.file + '"></th>';
                    html += '<td><code>' + file.file + '</code></td>';
                    html += '<td>' + (file.type || strings.unknown) + '</td>';
                    html += '<td><button type="button" class="button button-small vigilante-ignore-file" data-file="' + file.file + '">' + (strings.ignore || 'Ignore') + '</button></td>';
                    html += '</tr>';
                });
                html += '</tbody></table>';
                html += '</div>';
            }

            if (results.modified.length === 0 && results.suspicious.length === 0 && results.extra.length === 0) {
                html += '<div class="vigilante-all-clear"><span class="dashicons dashicons-yes-alt"></span> ' + strings.allClear + '</div>';
            }

            $container.html(html).show();

            // Initialize client-side pagination for file integrity tables
            this.initFileIntegrityPagination($container);
        },

        /**
         * Initialize client-side pagination for file integrity tables
         * Works on both PHP-rendered (last results) and JS-rendered (live scan) tables
         *
         * @param {jQuery} $scope Optional scope to limit search (for live scan results)
         */
        initFileIntegrityPagination: function($scope) {
            var perPage = 20;
            var $context = $scope || $(document);

            $context.find('table.vigilante-fi-paginated').each(function() {
                var $table = $(this);
                var $rows = $table.find('tbody tr');
                var total = $rows.length;

                if (total === 0) {
                    return;
                }

                // Store state on the parent container
                var $container = $table.closest('.vigilante-paginated-section');
                $container.data('fi-page', 1);
                $container.data('fi-per-page', perPage);
                $container.data('fi-total', total);

                // Hide rows beyond first page (only if more than perPage)
                if (total > perPage) {
                    $rows.each(function(index) {
                        $(this).toggle(index < perPage);
                    });
                }

                // Build pagination controls (always show count, buttons only when needed)
                var $wrap = $container.find('.vigilante-fi-pagination-wrap');
                var paginationHtml = Vigilante_Admin.buildFilePaginationHtml(1, perPage, total);
                $wrap.html(paginationHtml);
            });
        },

        /**
         * Build pagination HTML for file integrity tables
         */
        buildFilePaginationHtml: function(page, perPage, total) {
            var totalPages = Math.ceil(total / perPage) || 1;
            var from = total > 0 ? ((page - 1) * perPage) + 1 : 0;
            var to = Math.min(page * perPage, total);
            var needsNav = total > perPage;

            var text = total > 0
                ? (vigilanteAdmin.strings.paginationOf || '%1$d–%2$d of %3$d').replace('%1$d', from).replace('%2$d', to).replace('%3$d', total)
                : (vigilanteAdmin.strings.paginationEmpty || '0 items');

            var prevDisabled = page <= 1 ? ' disabled' : '';
            var nextDisabled = page >= totalPages ? ' disabled' : '';

            var html = '<span class="vigilante-pagination vigilante-fi-pagination">';
            if (needsNav) {
                html += '<button type="button" class="vigilante-page-first" title="First"' + prevDisabled + '>&laquo;</button>';
                html += '<button type="button" class="vigilante-page-prev" title="Previous"' + prevDisabled + '>&lsaquo;</button>';
            }
            html += '<span class="vigilante-page-info">' + text + '</span>';
            if (needsNav) {
                html += '<button type="button" class="vigilante-page-next" title="Next"' + nextDisabled + '>&rsaquo;</button>';
                html += '<button type="button" class="vigilante-page-last" title="Last"' + nextDisabled + '>&raquo;</button>';
            }
            html += '</span>';

            return html;
        },

        /**
         * Navigate file integrity table pages (client-side)
         */
        goToFilePage: function($container, direction) {
            var page = $container.data('fi-page') || 1;
            var perPage = $container.data('fi-per-page') || 20;
            var total = $container.data('fi-total') || 0;
            var totalPages = Math.ceil(total / perPage) || 1;

            switch (direction) {
                case 'first': page = 1; break;
                case 'prev':  page = Math.max(1, page - 1); break;
                case 'next':  page = Math.min(totalPages, page + 1); break;
                case 'last':  page = totalPages; break;
            }

            $container.data('fi-page', page);

            // Show/hide rows
            var start = (page - 1) * perPage;
            var end = start + perPage;
            $container.find('table.vigilante-fi-paginated tbody tr').each(function(index) {
                $(this).toggle(index >= start && index < end);
            });

            // Update controls
            var $wrap = $container.find('.vigilante-fi-pagination-wrap');
            $wrap.html(this.buildFilePaginationHtml(page, perPage, total));

            // Sync the "select all" header with what is now visible.
            // Selections in other pages remain checked and will be included
            // in any bulk action, but the header reflects only this page.
            var $allCb = $container.find('.vigilante-fi-cb-all');
            if ($allCb.length) {
                var $visible = $container.find('table.vigilante-fi-paginated tbody tr:visible .vigilante-fi-cb');
                var $checked = $visible.filter(':checked');
                $allCb.prop('checked', $visible.length > 0 && $checked.length === $visible.length);
            }
        },

        /**
         * Refresh file integrity pagination after row removal (ignore)
         */
        refreshFilePagination: function($container) {
            var perPage = $container.data('fi-per-page') || 20;
            var $rows = $container.find('table.vigilante-fi-paginated tbody tr');
            var total = $rows.length;

            $container.data('fi-total', total);

            if (total === 0) {
                $container.find('.vigilante-fi-pagination-wrap').empty();
                return;
            }

            if (total <= perPage) {
                // Show all rows, display count only
                $rows.show();
                $container.data('fi-page', 1);
                var $wrap = $container.find('.vigilante-fi-pagination-wrap');
                $wrap.html(this.buildFilePaginationHtml(1, perPage, total));
                return;
            }

            // Ensure current page is still valid
            var page = $container.data('fi-page') || 1;
            var totalPages = Math.ceil(total / perPage);
            if (page > totalPages) {
                page = totalPages;
            }
            $container.data('fi-page', page);

            // Show/hide rows for current page
            var start = (page - 1) * perPage;
            var end = start + perPage;
            $rows.each(function(index) {
                $(this).toggle(index >= start && index < end);
            });

            var $wrap = $container.find('.vigilante-fi-pagination-wrap');
            $wrap.html(this.buildFilePaginationHtml(page, perPage, total));
        },

        /**
         * Handle export settings
         */
        handleExportSettings: function(e) {
            e.preventDefault();

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_export_settings',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var blob = new Blob([response.data.content], { type: 'application/json' });
                        var url = URL.createObjectURL(blob);
                        var a = document.createElement('a');
                        a.href = url;
                        a.download = response.data.filename;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                }
            });
        },

        /**
         * Handle import settings click
         */
        handleImportSettings: function(e) {
            e.preventDefault();
            $('#vigilante-import-file').trigger('click');
        },

        /**
         * Handle import file selection
         */
        handleImportFile: function(e) {
            var file = e.target.files[0];
            if (!file) return;

            var reader = new FileReader();
            reader.onload = function(e) {
                if (!confirm(vigilanteAdmin.strings.confirm + ' ' + (vigilanteAdmin.strings.confirmOverwrite || 'This will overwrite your current settings.'))) {
                    return;
                }

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_import_settings',
                        nonce: vigilanteAdmin.nonce,
                        settings: e.target.result
                    },
                    success: function(response) {
                        if (response.success) {
                            Vigilante_Admin.showNotice('success', response.data);
                            setTimeout(function() {
                                location.reload();
                            }, 1000);
                        } else {
                            Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.importFailed);
                        }
                    },
                    error: function() {
                        Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.importFailed);
                    }
                });
            };
            reader.readAsText(file);
        },

        /**
         * Handle reset settings
         */
        handleResetSettings: function(e) {
            e.preventDefault();

            if (!confirm(vigilanteAdmin.strings.confirm + ' ' + (vigilanteAdmin.strings.confirmResetAll || 'This will reset ALL settings to defaults.'))) {
                return;
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_apply_preset',
                    nonce: vigilanteAdmin.nonce,
                    preset: 'reset'
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.settingsResetDefaults || 'Settings reset to defaults.');
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                }
            });
        },

        /**
         * Handle test headers
         */
        handleTestHeaders: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var $results = $('#vigilante-headers-result');

            $btn.prop('disabled', true).html(vigilanteAdmin.strings.testing + ' <span class="vigilante-spinner"></span>');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_test_headers',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.displayHeaderResults(response.data, $results);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.testHeaders);
                }
            });
        },

        /**
         * Handle login URL notification button
         */
        handleNotifyLoginUrl: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var $status = $btn.siblings('.vigilante-login-url-notify-status');

            $btn.prop('disabled', true).text(vigilanteAdmin.strings.sending || 'Sending...');
            $status.removeClass('success error').text('');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_notify_login_url',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        var msg = response.data.sent + ' ' + (vigilanteAdmin.strings.notificationsSent || 'notifications sent');
                        if (response.data.failed > 0) {
                            msg += ', ' + response.data.failed + ' ' + (vigilanteAdmin.strings.failed || 'failed');
                        }
                        $status.addClass('success').text(msg);
                    } else {
                        $status.addClass('error').text(response.data || 'Error');
                    }
                },
                error: function() {
                    $status.addClass('error').text('Error');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.sendNotification || 'Send notification now');
                }
            });
        },

        /**
         * Toggle login URL notification section based on URL input
         */
        handleLoginUrlToggle: function() {
            var hasUrl = $('#vigilante_custom_login_url').val().trim().length > 0;
            $('.vigilante-login-url-notify-wrapper').toggleClass('vigilante-login-url-notify-disabled', !hasUrl);
            $('.vigilante-login-url-preview').toggle(hasUrl);
        },

        /**
         * Display header test results
         */
        displayHeaderResults: function(results, $container) {
            var gradeClass = 'vigilante-grade-' + results.grade.toLowerCase();
            var html = '<div class="vigilante-security-score" style="text-align: center; padding: 20px;">';
            html += '<div class="vigilante-score-circle ' + gradeClass + '">';
            html += '<span class="vigilante-grade">' + results.grade + '</span>';
            html += '</div>';
            html += '<p style="text-align: center;"><strong>' + vigilanteAdmin.strings.score + ':</strong> ' + Math.round(results.score) + '%</p>';
            html += '</div>';

            if (results.headers.length > 0) {
                html += '<p><strong>' + vigilanteAdmin.strings.enabledHeaders + ':</strong></p><ul>';
                results.headers.forEach(function(header) {
                    html += '<li class="enabled">&#10003; ' + header + '</li>';
                });
                html += '</ul>';
            }

            if (results.missing.length > 0) {
                html += '<p><strong>' + vigilanteAdmin.strings.missingHeaders + ':</strong></p><ul>';
                results.missing.forEach(function(header) {
                    html += '<li class="missing">&#10007; ' + header + '</li>';
                });
                html += '</ul>';
            }

            if (results.warnings && results.warnings.length > 0) {
                html += '<p><strong>' + vigilanteAdmin.strings.warnings + ':</strong></p><ul>';
                results.warnings.forEach(function(warning) {
                    html += '<li class="warning">&#9888; ' + warning + '</li>';
                });
                html += '</ul>';
            }

            $container.html(html).addClass('visible');
        },

        /**
         * Handle activity log filter
         */
        handleLogFilter: function() {
            this.logPage = 1;
            this.loadActivityLogs();
        },

        /**
         * Handle activity log search with debounce (400ms, min 3 chars)
         */
        handleLogSearch: function() {
            var self = this;
            clearTimeout(this.logSearchTimer);
            this.logSearchTimer = setTimeout(function() {
                var term = $('#vigilante-log-search').val().trim();
                // Only search with 3+ chars, or clear search when empty
                if (term.length >= 3 || term.length === 0) {
                    self.logPage = 1;
                    self.loadActivityLogs();
                }
            }, 400);
        },

        /**
         * Load activity logs via AJAX (with filters and pagination)
         */
        loadActivityLogs: function() {
            var type = $('#vigilante-log-type-filter').val();
            var severity = $('#vigilante-log-severity-filter').val();
            var method = $('#vigilante-log-method-filter').val();
            var search = $('#vigilante-log-search').val();
            var $refreshBtn = $('#vigilante-log-refresh');

            // Visual feedback
            $refreshBtn.prop('disabled', true).addClass('updating-message');

            var data = {
                action: 'vigilante_get_logs',
                nonce: vigilanteAdmin.nonce,
                per_page: this.logPerPage,
                page: this.logPage,
                type: type,
                severity: severity
            };

            if (method) {
                data.request_method = method;
            }

            if (search && search.trim().length >= 3) {
                data.search = search.trim();
            }

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: data,
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.renderLogTable(response.data.logs);
                        Vigilante_Admin.updateLogPagination(response.data.total);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data || vigilanteAdmin.strings.error);
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error || 'Request failed');
                },
                complete: function() {
                    $refreshBtn.prop('disabled', false).removeClass('updating-message');
                }
            });
        },

        /**
         * Navigate activity log pages
         */
        goToLogPage: function(direction) {
            var $pagination = $('#vigilante-log-pagination');
            var total = parseInt($pagination.attr('data-total'), 10) || 0;
            var totalPages = Math.ceil(total / this.logPerPage) || 1;

            switch (direction) {
                case 'first': this.logPage = 1; break;
                case 'prev':  this.logPage = Math.max(1, this.logPage - 1); break;
                case 'next':  this.logPage = Math.min(totalPages, this.logPage + 1); break;
                case 'last':  this.logPage = totalPages; break;
            }

            this.loadActivityLogs();
        },

        /**
         * Update activity log pagination controls
         */
        updateLogPagination: function(total) {
            var $pagination = $('#vigilante-log-pagination');
            total = parseInt(total, 10) || 0;
            var totalPages = Math.ceil(total / this.logPerPage) || 1;
            var needsNav = total > this.logPerPage;

            $pagination.attr('data-total', total);
            $pagination.attr('data-page', this.logPage);

            var from = total > 0 ? ((this.logPage - 1) * this.logPerPage) + 1 : 0;
            var to = Math.min(this.logPage * this.logPerPage, total);

            var text = total > 0
                ? (vigilanteAdmin.strings.paginationOf || '%1$d–%2$d of %3$d').replace('%1$d', from).replace('%2$d', to).replace('%3$d', total)
                : (vigilanteAdmin.strings.paginationEmpty || '0 items');

            var prevDisabled = this.logPage <= 1 ? ' disabled' : '';
            var nextDisabled = this.logPage >= totalPages ? ' disabled' : '';

            var html = '';
            if (needsNav) {
                html += '<button type="button" class="vigilante-page-first"' + prevDisabled + '>&laquo;</button>';
                html += '<button type="button" class="vigilante-page-prev"' + prevDisabled + '>&lsaquo;</button>';
            }
            html += '<span class="vigilante-page-info">' + text + '</span>';
            if (needsNav) {
                html += '<button type="button" class="vigilante-page-next"' + nextDisabled + '>&rsaquo;</button>';
                html += '<button type="button" class="vigilante-page-last"' + nextDisabled + '>&raquo;</button>';
            }

            $pagination.html(html);
        },

        /**
         * Render log table
         */
        renderLogTable: function(logs) {
            var $tbody = $('#vigilante-activity-log-table tbody');
            $tbody.empty();

            if (logs.length === 0) {
                $tbody.append('<tr><td colspan="8">' + (vigilanteAdmin.strings.noLogEntries || 'No log entries found.') + '</td></tr>');
                return;
            }

            var self = this;
            var typeLabels = (vigilanteAdmin.strings && vigilanteAdmin.strings.eventTypeLabels) || {};
            var severityLabels = (vigilanteAdmin.strings && vigilanteAdmin.strings.severityLabels) || {};

            logs.forEach(function(log) {
                var details = {
                    id: log.id,
                    type: log.event_type || '',
                    action: log.event_action || '',
                    message: log.event_message || '',
                    user: log.user_login || '',
                    ip: log.ip_address || '',
                    user_agent: log.user_agent || '',
                    request_method: log.request_method || '',
                    date: log.created_at || '',
                    severity: log.severity || 'info',
                    is_ip_whitelisted: !!log.is_ip_whitelisted,
                    is_ip_blacklisted: !!log.is_ip_blacklisted,
                    is_ua_whitelisted: !!log.is_ua_whitelisted,
                    is_ua_blacklisted: !!log.is_ua_blacklisted
                };

                var displayType = typeLabels[log.event_type] || log.event_type;
                var displaySeverity = severityLabels[log.severity] || log.severity;

                var methodHtml = '-';
                if (log.request_method) {
                    methodHtml = '<span class="vigilante-method-label vigilante-method-' + self.escapeHtml(log.request_method.toLowerCase()) + '">' + self.escapeHtml(log.request_method) + '</span>';
                }

                var row = '<tr class="vigilante-severity-' + self.escapeHtml(log.severity) + '">';
                row += '<td>' + self.escapeHtml(log.created_at) + '</td>';
                row += '<td>' + self.escapeHtml(displayType) + '</td>';
                row += '<td>' + methodHtml + '</td>';
                row += '<td><span class="vigilante-badge vigilante-badge-' + self.escapeHtml(log.severity) + '">' + self.escapeHtml(displaySeverity) + '</span></td>';
                row += '<td>' + self.escapeHtml(log.event_message) + '</td>';
                row += '<td>' + self.escapeHtml(log.user_login || '-') + '</td>';
                row += '<td><code>' + self.escapeHtml(log.ip_address) + '</code></td>';
                row += '<td><button type="button" class="button button-small vigilante-view-log-details" data-details=\'' + self.escapeHtml(JSON.stringify(details)) + '\'>' + (vigilanteAdmin.strings.view || 'View') + '</button></td>';
                row += '</tr>';
                $tbody.append(row);
            });
        },

        /**
         * Handle export logs
         */
        handleExportLogs: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var type = $('#vigilante-log-type-filter').val();
            var severity = $('#vigilante-log-severity-filter').val();
            var method = $('#vigilante-log-method-filter').val();
            var search = $('#vigilante-log-search').val();

            var data = {
                action: 'vigilante_get_logs',
                nonce: vigilanteAdmin.nonce,
                per_page: 9999
            };

            // Only add filters if they have values
            if (type && type !== '') {
                data.type = type;
            }
            if (severity && severity !== '') {
                data.severity = severity;
            }
            if (method && method !== '') {
                data.request_method = method;
            }
            if (search && search.trim().length >= 3) {
                data.search = search.trim();
            }

            $btn.prop('disabled', true).text(vigilanteAdmin.strings.exporting || 'Exporting...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: data,
                success: function(response) {
                    if (response.success && response.data.logs && response.data.logs.length > 0) {
                        Vigilante_Admin.downloadCSV(response.data.logs);
                        Vigilante_Admin.showNotice('success', (vigilanteAdmin.strings.logsExported || 'Logs exported (%d entries)').replace('%d', response.data.logs.length));
                    } else {
                        Vigilante_Admin.showNotice('warning', vigilanteAdmin.strings.noLogsToExport || 'No logs to export');
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.exportFailed || 'Export failed');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.exportLogs || 'Export Logs');
                }
            });
        },

        /**
         * Download logs as CSV
         */
        downloadCSV: function(logs) {
            var csv = 'Date,Type,Method,Severity,Message,User,IP\n';
            
            logs.forEach(function(log) {
                csv += '"' + log.created_at + '",';
                csv += '"' + log.event_type + '",';
                csv += '"' + (log.request_method || '') + '",';
                csv += '"' + log.severity + '",';
                csv += '"' + (log.event_message || '').replace(/"/g, '""') + '",';
                csv += '"' + (log.user_login || '') + '",';
                csv += '"' + log.ip_address + '"\n';
            });

            var blob = new Blob([csv], { type: 'text/csv' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'activity-log-' + new Date().toISOString().slice(0, 10) + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        /**
         * Handle create backup
         */
        handleCreateBackup: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true).html(vigilanteAdmin.strings.loading + ' <span class="vigilante-spinner"></span>');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_create_backup',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.backupCreated || 'Backup created successfully.');
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.createBackupNow || 'Create Backup Now');
                }
            });
        },

        // =================================================================
        // DATABASE BACKUP HANDLERS
        // =================================================================

        /**
         * Toggle database backup panel and load tables
         */
        handleDbBackupToggle: function(e) {
            e.preventDefault();

            var $panel = $('.vigilante-db-backup-panel');
            var $btn = $(e.currentTarget);

            if ($panel.is(':visible')) {
                $panel.slideUp(200);
                return;
            }

            $panel.slideDown(200);

            // Load tables if not already loaded
            if ($panel.find('.vigilante-db-tables-content').is(':hidden')) {
                this.loadDbTables();
            }
        },

        /**
         * Handle settings search input
         */
        searchActiveIndex: -1,

        handleSettingsSearch: function(e) {
            var query = ($('#vigilante-settings-search').val() || '').trim().toLowerCase();
            var $results = $('#vigilante-settings-search-results');
            var index = (vigilanteAdmin.searchIndex || []);

            if (query.length < 2) {
                $results.attr('hidden', true).empty();
                this.searchActiveIndex = -1;
                return;
            }

            var matches = [];
            for (var i = 0; i < index.length; i++) {
                var entry = index[i];
                var label = (entry.label || '').toLowerCase();
                var labelEn = (entry.label_en || '').toLowerCase();
                var section = (entry.section || '').toLowerCase();
                var keywords = (entry.keywords || '').toLowerCase();
                if (label.indexOf(query) !== -1 || labelEn.indexOf(query) !== -1 || section.indexOf(query) !== -1 || keywords.indexOf(query) !== -1) {
                    matches.push(entry);
                }
                if (matches.length >= 30) {
                    break;
                }
            }

            if (!matches.length) {
                $results.html('<div class="vigilante-search-empty">' + (vigilanteAdmin.strings.searchNoResults || 'No results') + '</div>').attr('hidden', false);
                this.searchActiveIndex = -1;
                return;
            }

            // Group by tab
            var grouped = {};
            var tabOrder = [];
            for (var j = 0; j < matches.length; j++) {
                var m = matches[j];
                if (!grouped[m.tab]) {
                    grouped[m.tab] = { label: m.tab_label, items: [] };
                    tabOrder.push(m.tab);
                }
                grouped[m.tab].items.push(m);
            }

            var html = '';
            var flatIdx = 0;
            for (var k = 0; k < tabOrder.length; k++) {
                var tab = tabOrder[k];
                var group = grouped[tab];
                html += '<div class="vigilante-search-group">';
                html += '<div class="vigilante-search-group-title">' + this.escapeHtml(group.label) + '</div>';
                for (var n = 0; n < group.items.length; n++) {
                    var it = group.items[n];
                    var base = (vigilanteAdmin.adminUrl || 'admin.php?page=vigilante');
                    var href = base + '&tab=' + encodeURIComponent(it.tab) + '#' + encodeURIComponent(it.anchor);
                    var activeClass = flatIdx === 0 ? ' vigilante-search-item-active' : '';
                    html += '<a class="vigilante-search-item' + activeClass + '" data-idx="' + flatIdx + '" role="option" href="' + href + '">';
                    html += '<span class="vigilante-search-item-label">' + this.escapeHtml(it.label) + '</span>';
                    html += '<span class="vigilante-search-item-section">' + this.escapeHtml(it.section) + '</span>';
                    html += '</a>';
                    flatIdx++;
                }
                html += '</div>';
            }

            $results.html(html).attr('hidden', false);
            this.searchActiveIndex = 0;
        },

        /**
         * Handle keyboard navigation in search: arrows move highlight, Enter navigates, Escape closes
         */
        handleSettingsSearchKey: function(e) {
            var $items = $('#vigilante-settings-search-results .vigilante-search-item');

            if (e.key === 'Escape') {
                $('#vigilante-settings-search-results').attr('hidden', true);
                $('#vigilante-settings-search').blur();
                return;
            }

            if (!$items.length) return;

            if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.searchActiveIndex = Math.min(this.searchActiveIndex + 1, $items.length - 1);
                this.updateSearchActive();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.searchActiveIndex = Math.max(this.searchActiveIndex - 1, 0);
                this.updateSearchActive();
            } else if (e.key === 'Home') {
                e.preventDefault();
                this.searchActiveIndex = 0;
                this.updateSearchActive();
            } else if (e.key === 'End') {
                e.preventDefault();
                this.searchActiveIndex = $items.length - 1;
                this.updateSearchActive();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                var idx = this.searchActiveIndex >= 0 ? this.searchActiveIndex : 0;
                var $target = $items.eq(idx);
                if ($target.length) {
                    window.location.href = $target.attr('href');
                }
            }
        },

        /**
         * Sync active highlight when user hovers a search result
         */
        handleSettingsSearchHover: function(e) {
            var idx = parseInt($(e.currentTarget).attr('data-idx'), 10);
            if (isNaN(idx)) return;
            this.searchActiveIndex = idx;
            this.updateSearchActive(false);
        },

        /**
         * Apply the active class to the current index and scroll it into view
         */
        updateSearchActive: function(scroll) {
            var $items = $('#vigilante-settings-search-results .vigilante-search-item');
            $items.removeClass('vigilante-search-item-active');
            var $active = $items.eq(this.searchActiveIndex);
            if (!$active.length) return;
            $active.addClass('vigilante-search-item-active');
            if (scroll !== false && $active[0] && typeof $active[0].scrollIntoView === 'function') {
                $active[0].scrollIntoView({ block: 'nearest' });
            }
        },

        /**
         * Format bytes as a human-readable size
         */
        formatBytes: function(bytes) {
            if (!bytes || bytes < 0) return '0 B';
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var i = 0;
            var n = bytes;
            while (n >= 1024 && i < units.length - 1) {
                n = n / 1024;
                i++;
            }
            return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + ' ' + units[i];
        },

        /**
         * Update DB tables info: count + total size
         */
        updateDbTablesInfo: function() {
            var $boxes = $('.vigilante-db-table-check');
            var total = $boxes.length;
            if (!total) {
                $('.vigilante-db-tables-info').text('');
                return;
            }
            var $checked = $boxes.filter(':checked');
            var checkedCount = $checked.length;
            var bytes = 0;
            $checked.each(function() {
                bytes += parseInt($(this).attr('data-bytes'), 10) || 0;
            });
            var sizeStr = Vigilante_Admin.formatBytes(bytes);
            var tpl;
            if (checkedCount === total) {
                tpl = vigilanteAdmin.strings.dbTablesTotal || '%1$d tables total (%2$s)';
                $('.vigilante-db-tables-info').text(tpl.replace('%1$d', total).replace('%2$s', sizeStr));
            } else {
                tpl = vigilanteAdmin.strings.dbTablesSelected || '%1$d tables selected (%2$s)';
                $('.vigilante-db-tables-info').text(tpl.replace('%1$d', checkedCount).replace('%2$s', sizeStr));
            }
        },

        /**
         * Load database tables via AJAX
         */
        loadDbTables: function() {
            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_get_db_tables',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (!response.success) {
                        Vigilante_Admin.showNotice('error', response.data);
                        return;
                    }

                    var data = response.data;
                    var coreHtml = '';
                    var otherHtml = '';

                    // Build core tables checkboxes
                    if (data.core && data.core.length) {
                        $.each(data.core, function(i, table) {
                            coreHtml += '<label class="vigilante-db-table-label">';
                            coreHtml += '<input type="checkbox" class="vigilante-db-table-check" value="' + table.name + '" data-bytes="' + (table.bytes || 0) + '" checked>';
                            coreHtml += '<span class="vigilante-db-table-name" title="' + table.name + '">' + table.short + '</span>';
                            coreHtml += '<span class="vigilante-db-table-meta">' + table.rows + ' rows &middot; ' + table.size + '</span>';
                            coreHtml += '</label>';
                        });
                    }

                    // Build other tables checkboxes
                    if (data.other && data.other.length) {
                        $.each(data.other, function(i, table) {
                            otherHtml += '<label class="vigilante-db-table-label">';
                            otherHtml += '<input type="checkbox" class="vigilante-db-table-check" value="' + table.name + '" data-bytes="' + (table.bytes || 0) + '" checked>';
                            otherHtml += '<span class="vigilante-db-table-name" title="' + table.name + '">' + table.short + '</span>';
                            otherHtml += '<span class="vigilante-db-table-meta">' + table.rows + ' rows &middot; ' + table.size + '</span>';
                            otherHtml += '</label>';
                        });
                        $('#vigilante-db-other-group').show();
                    }

                    $('#vigilante-db-core-tables').html(coreHtml);
                    $('#vigilante-db-other-tables').html(otherHtml);

                    Vigilante_Admin.updateDbTablesInfo();

                    $('.vigilante-db-tables-loading').hide();
                    $('.vigilante-db-tables-content').show();
                }
            });
        },

        /**
         * Select/deselect all tables
         */
        handleDbSelectAll: function(e) {
            var checked = $(e.currentTarget).prop('checked');
            $('.vigilante-db-table-check').prop('checked', checked);
            this.updateDbTablesInfo();
        },

        /**
         * Update select-all state when individual checkbox changes
         */
        handleDbTableCheck: function() {
            var total = $('.vigilante-db-table-check').length;
            var checked = $('.vigilante-db-table-check:checked').length;
            $('#vigilante-db-select-all').prop('checked', total === checked);
            this.updateDbTablesInfo();
        },

        /**
         * Download database backup
         */
        handleDbBackupDownload: function(e) {
            e.preventDefault();

            var tables = [];
            $('.vigilante-db-table-check:checked').each(function() {
                tables.push($(this).val());
            });

            if (tables.length === 0) {
                Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.dbBackupNoTables);
                return;
            }

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true).html(vigilanteAdmin.strings.dbBackupDownloading + ' <span class="vigilante-spinner"></span>');

            // Submit via hidden form for direct file download
            var $form = $('<form>', {
                method: 'POST',
                action: vigilanteAdmin.ajaxUrl
            });

            $form.append($('<input>', { type: 'hidden', name: 'action', value: 'vigilante_download_db_backup' }));
            $form.append($('<input>', { type: 'hidden', name: 'nonce', value: vigilanteAdmin.nonce }));
            $form.append($('<input>', { type: 'hidden', name: 'tables', value: tables.join(',') }));

            $('body').append($form);
            $form.submit();
            $form.remove();

            // Re-enable button after a delay (download starts in background)
            setTimeout(function() {
                $btn.prop('disabled', false).text($btn.data('original-text') || vigilanteAdmin.strings.downloadBackup || 'Download Backup (.zip)');
                Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.dbBackupSuccess);
            }, 3000);
        },

        // =================================================================
        // DATABASE PREFIX HANDLERS
        // =================================================================

        /**
         * Regenerate random prefix
         */
        handleDbRegeneratePrefix: function(e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true);

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_generate_prefix',
                    nonce: vigilanteAdmin.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $('#vigilante-new-prefix').text(response.data.prefix);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                    }
                },
                complete: function() {
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Toggle the change prefix button based on checkbox
         */
        handleDbPrefixConfirmToggle: function(e) {
            var checked = $(e.currentTarget).prop('checked');
            $('.vigilante-db-change-prefix').prop('disabled', !checked);
        },

        /**
         * Change database prefix
         */
        handleDbChangePrefix: function(e) {
            e.preventDefault();

            // Verify checkbox is checked
            if (!$('#vigilante-prefix-backup-confirm').prop('checked')) {
                Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.dbPrefixCheckbox);
                return;
            }

            var newPrefix = $('#vigilante-new-prefix').text().trim();

            if (!confirm(vigilanteAdmin.strings.dbPrefixConfirm)) {
                return;
            }

            var $btn = $(e.currentTarget);
            $btn.prop('disabled', true).html(vigilanteAdmin.strings.dbPrefixChanging + ' <span class="vigilante-spinner"></span>');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_change_prefix',
                    nonce: vigilanteAdmin.nonce,
                    prefix: newPrefix
                },
                success: function(response) {
                    if (response.success) {
                        Vigilante_Admin.showNotice('success', vigilanteAdmin.strings.dbPrefixSuccess);
                        // Reload page after prefix change (session will still work)
                        setTimeout(function() {
                            location.reload();
                        }, 2000);
                    } else {
                        Vigilante_Admin.showNotice('error', response.data);
                        $btn.prop('disabled', false).text($btn.data('original-text'));
                    }
                },
                error: function() {
                    Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                    $btn.prop('disabled', false).text($btn.data('original-text'));
                }
            });
        },

        /**
         * Show notice
         */
        showNotice: function(type, message) {
            // Remove any existing notices first.
            $('.vigilante-notice').remove();

            var $notice = $('<div class="vigilante-notice vigilante-notice-' + type + '">' + message + '</div>');
            $('.vigilante-main').prepend($notice);

            // Scroll to top of the settings area so user sees the notice.
            $('html, body').animate({
                scrollTop: $('.vigilante-admin-wrap').offset().top - 50
            }, 300);

            setTimeout(function() {
                $notice.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        },

        /**
         * Handle view log details
         */
        handleViewLogDetails: function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            var $btn = $(e.currentTarget);
            var detailsStr = $btn.attr('data-details');

            if (!detailsStr) {
                return;
            }

            var details;
            try {
                details = JSON.parse(detailsStr);
            } catch (err) {
                return;
            }

            var html = '';

            var s = vigilanteAdmin.strings;

            // -- Section: Request --
            html += '<div class="vigilante-popup-section">';
            html += '<h4 class="vigilante-popup-section-title">' + this.escapeHtml(s.logRequest || 'Request') + '</h4>';
            html += '<table class="vigilante-details-table">';
            html += '<tr><th>' + this.escapeHtml(s.logDate || 'Date') + '</th><td>' + this.escapeHtml(details.date) + '</td></tr>';
            if (details.request_method) {
                html += '<tr><th>' + this.escapeHtml(s.logMethod || 'Method') + '</th><td><span class="vigilante-method-label vigilante-method-' + this.escapeHtml(details.request_method.toLowerCase()) + '">' + this.escapeHtml(details.request_method) + '</span></td></tr>';
            }
            html += '<tr><th>' + this.escapeHtml(s.logType || 'Type') + '</th><td>' + this.escapeHtml(details.type) + '</td></tr>';
            html += '<tr><th>' + this.escapeHtml(s.logAction || 'Action') + '</th><td>' + this.escapeHtml(details.action || '-') + '</td></tr>';
            html += '<tr><th>' + this.escapeHtml(s.logSeverity || 'Severity') + '</th><td><span class="vigilante-badge vigilante-badge-' + this.escapeHtml(details.severity || 'info') + '">' + this.escapeHtml(details.severity || 'info') + '</span></td></tr>';
            html += '<tr><th>' + this.escapeHtml(s.logMessage || 'Message') + '</th><td>' + this.escapeHtml(details.message) + '</td></tr>';
            html += '</table>';
            html += '</div>';

            // -- Section: Client --
            html += '<div class="vigilante-popup-section">';
            html += '<h4 class="vigilante-popup-section-title">' + this.escapeHtml(s.logClient || 'Client') + '</h4>';
            html += '<table class="vigilante-details-table">';
            html += '<tr><th>' + this.escapeHtml(s.logUser || 'User') + '</th><td>' + this.escapeHtml(details.user || '-') + '</td></tr>';

            // IP with lookup link
            if (details.ip && details.ip !== '0.0.0.0') {
                var ipEscaped = this.escapeHtml(details.ip);
                html += '<tr><th>' + this.escapeHtml(s.logIpAddress || 'IP Address') + '</th><td>';
                html += '<code>' + ipEscaped + '</code> ';
                html += '<a href="https://abuseipdb.com/check/' + encodeURIComponent(details.ip) + '" target="_blank" rel="noopener noreferrer" class="vigilante-ip-lookup" title="Lookup IP">';
                html += '<span class="dashicons dashicons-search"></span></a>';
                html += '</td></tr>';
            } else {
                html += '<tr><th>' + this.escapeHtml(s.logIpAddress || 'IP Address') + '</th><td><code>' + this.escapeHtml(details.ip) + '</code></td></tr>';
            }
            
            if (details.user_agent) {
                html += '<tr><th>' + this.escapeHtml(s.logUserAgent || 'User Agent') + '</th><td class="vigilante-ua-cell"><code>' + this.escapeHtml(details.user_agent) + '</code></td></tr>';
            }
            html += '</table>';

            // Action buttons for IP and UA
            html += '<div class="vigilante-popup-actions">';
            if (details.ip && details.ip !== '0.0.0.0') {
                html += '<span class="vigilante-popup-actions-label">' + this.escapeHtml(s.logIpLabel || 'IP:') + '</span>';
                if (details.is_ip_whitelisted) {
                    html += '<button type="button" class="button button-small vigilante-btn-added" disabled><span class="dashicons dashicons-yes-alt"></span> ' + this.escapeHtml(s.logInWhitelist || 'In whitelist') + '</button> ';
                } else {
                    html += '<button type="button" class="button button-small vigilante-add-to-list" data-item-type="ip" data-list-type="whitelist" data-value="' + this.escapeHtml(details.ip) + '"><span class="dashicons dashicons-yes-alt"></span> ' + this.escapeHtml(s.logWhitelist || 'Whitelist') + '</button> ';
                }
                if (details.is_ip_blacklisted) {
                    html += '<button type="button" class="button button-small vigilante-btn-added" disabled><span class="dashicons dashicons-dismiss"></span> ' + this.escapeHtml(s.logInBlacklist || 'In blacklist') + '</button> ';
                } else {
                    html += '<button type="button" class="button button-small vigilante-add-to-list vigilante-btn-danger" data-item-type="ip" data-list-type="blacklist" data-value="' + this.escapeHtml(details.ip) + '"><span class="dashicons dashicons-dismiss"></span> ' + this.escapeHtml(s.logBlacklist || 'Blacklist') + '</button> ';
                }
            }
            if (details.user_agent) {
                html += '<span class="vigilante-popup-actions-label">' + this.escapeHtml(s.logUaLabel || 'UA:') + '</span>';
                if (details.is_ua_whitelisted) {
                    html += '<button type="button" class="button button-small vigilante-btn-added" disabled><span class="dashicons dashicons-yes-alt"></span> ' + this.escapeHtml(s.logInWhitelist || 'In whitelist') + '</button> ';
                } else {
                    html += '<button type="button" class="button button-small vigilante-add-to-list" data-item-type="ua" data-list-type="whitelist" data-value="' + this.escapeHtml(details.user_agent) + '"><span class="dashicons dashicons-yes-alt"></span> ' + this.escapeHtml(s.logWhitelist || 'Whitelist') + '</button> ';
                }
                if (details.is_ua_blacklisted) {
                    html += '<button type="button" class="button button-small vigilante-btn-added" disabled><span class="dashicons dashicons-dismiss"></span> ' + this.escapeHtml(s.logInBlacklist || 'In blacklist') + '</button>';
                } else {
                    html += '<button type="button" class="button button-small vigilante-add-to-list vigilante-btn-danger" data-item-type="ua" data-list-type="blacklist" data-value="' + this.escapeHtml(details.user_agent) + '"><span class="dashicons dashicons-dismiss"></span> ' + this.escapeHtml(s.logBlacklist || 'Blacklist') + '</button>';
                }
            }
            html += '</div>';
            html += '<div class="vigilante-popup-feedback" style="display:none;"></div>';
            html += '</div>';

            // Event ID for reference
            html += '<div class="vigilante-popup-footer">';
            html += '<span class="vigilante-popup-id">ID: ' + this.escapeHtml(details.id) + '</span>';
            html += '</div>';

            $('#vigilante-log-details-content').html(html);
            $('#vigilante-log-details-modal').fadeIn(200);
        },

        /**
         * Handle adding IP or UA to firewall whitelist/blacklist
         */
        handleAddToFirewallList: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var itemType = $btn.data('item-type');
            var listType = $btn.data('list-type');
            var value = $btn.data('value');

            if (!itemType || !listType || !value) {
                return;
            }

            $btn.prop('disabled', true);

            var self = this;
            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_add_to_firewall_list',
                    nonce: vigilanteAdmin.nonce,
                    item_type: itemType,
                    list_type: listType,
                    value: value
                },
                success: function(response) {
                    var $feedback = $('.vigilante-popup-feedback');
                    if (response.success) {
                        $btn.text(vigilanteAdmin.strings.logAdded || 'Added!').addClass('vigilante-btn-added');
                        $feedback.html('<span class="vigilante-popup-msg vigilante-popup-msg-success">' + response.data + '</span>').slideDown(150);
                    } else {
                        $btn.prop('disabled', false);
                        $feedback.html('<span class="vigilante-popup-msg vigilante-popup-msg-warning">' + (response.data || vigilanteAdmin.strings.logErrorAddingToList || 'Error adding to list') + '</span>').slideDown(150);
                    }
                },
                error: function() {
                    $btn.prop('disabled', false);
                    $('.vigilante-popup-feedback').html('<span class="vigilante-popup-msg vigilante-popup-msg-error">' + (vigilanteAdmin.strings.logRequestFailed || 'Request failed') + '</span>').slideDown(150);
                }
            });
        },

        /**
         * Handle unblock firewall IP
         */
        handleUnblockFirewallIp: function(e) {
            var $btn = $(e.currentTarget);
            var ip = $btn.data('ip');

            if (!confirm(vigilanteAdmin.strings.confirmUnblockIp || 'Unblock this IP?')) {
                return;
            }

            $btn.prop('disabled', true).text(vigilanteAdmin.strings.loading || 'Loading...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_unblock_firewall_ip',
                    nonce: vigilanteAdmin.nonce,
                    ip: ip
                },
                success: function(response) {
                    if (response.success) {
                        $btn.closest('tr').fadeOut(300, function() {
                            var $tbody = $(this).closest('tbody');
                            $(this).remove();
                            // Hide the whole section if no more blocked IPs
                            if ($tbody.children('tr').length === 0) {
                                $tbody.closest('.vigilante-lockout-section').fadeOut(300);
                            }
                        });
                    } else {
                        alert(response.data || 'Error');
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.unblock || 'Unblock');
                    }
                },
                error: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.unblock || 'Unblock');
                }
            });
        },

        /**
         * Handle close modal
         */
        handleCloseModal: function(e) {
            if ($(e.target).hasClass('vigilante-modal') || $(e.target).hasClass('vigilante-modal-close')) {
                $('.vigilante-modal').hide();
            }
        },

        /**
         * Escape HTML
         */
        escapeHtml: function(text) {
            if (text === null || text === undefined) return '';
            if (typeof text !== 'string') {
                text = String(text);
            }
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        /**
         * Debounce function
         */
        debounce: function(func, wait) {
            var timeout;
            return function() {
                var context = this, args = arguments;
                clearTimeout(timeout);
                timeout = setTimeout(function() {
                    func.apply(context, args);
                }, wait);
            };
        },

        // =================================================================
        // Force Password Reset functionality
        // =================================================================

        /**
         * Selected users for password reset
         */
        selectedPasswordResetUsers: [],

        /**
         * Initialize password reset handlers
         */
        initPasswordReset: function() {
            var self = this;

            // User search for password reset
            var searchTimeout;
            $(document).on('input', '#vigilante-password-reset-search', function() {
                var query = $(this).val();
                clearTimeout(searchTimeout);
                
                if (query.length < 2) {
                    $('#vigilante-password-reset-results').hide().empty();
                    return;
                }

                searchTimeout = setTimeout(function() {
                    self.searchUsersForPasswordReset(query);
                }, 300);
            });

            // Close search results when clicking outside
            $(document).on('click', function(e) {
                if (!$(e.target).closest('.vigilante-user-search-wrapper').length) {
                    $('#vigilante-password-reset-results').hide();
                }
            });

            // Reset selected users button
            $(document).on('click', '#vigilante-reset-selected-users', function(e) {
                e.preventDefault();
                self.forceResetSelectedUsers();
            });

            // Reset all users button
            $(document).on('click', '#vigilante-reset-all-users', function(e) {
                e.preventDefault();
                self.forceResetAllUsers();
            });

            // Reset by role - checkbox change
            $(document).on('change', '.vigilante-reset-role-checkbox', function() {
                self.updateRoleResetSummary();
            });

            // Reset by role button
            $(document).on('click', '#vigilante-reset-by-role', function(e) {
                e.preventDefault();
                self.forceResetByRoles();
            });
        },

        /**
         * Search users for password reset
         */
        searchUsersForPasswordReset: function(query) {
            var self = this;
            var $results = $('#vigilante-password-reset-results');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_search_users_password_reset',
                    nonce: vigilanteAdmin.nonce,
                    query: query
                },
                success: function(response) {
                    if (response.success && response.data.length > 0) {
                        var html = '<ul class="vigilante-user-search-list">';
                        response.data.forEach(function(user) {
                            var isSelected = self.selectedPasswordResetUsers.indexOf(user.ID) !== -1;
                            html += '<li data-user-id="' + user.ID + '" class="' + (isSelected ? 'selected' : '') + '">';
                            html += '<img src="' + self.escapeHtml(user.avatar) + '" alt="" class="vigilante-user-avatar">';
                            html += '<div class="vigilante-user-info">';
                            html += '<strong>' + self.escapeHtml(user.display_name) + '</strong>';
                            html += '<br><small>' + self.escapeHtml(user.user_login) + ' - ' + self.escapeHtml(user.user_email) + '</small>';
                            html += '<br><small class="vigilante-user-roles">' + self.escapeHtml(user.roles) + '</small>';
                            html += '</div>';
                            html += '</li>';
                        });
                        html += '</ul>';
                        $results.html(html).show();

                        // Handle user selection
                        $results.find('li').on('click', function() {
                            var userId = parseInt($(this).data('user-id'));
                            var userName = $(this).find('strong').text();
                            var userEmail = $(this).find('small').first().text();
                            self.togglePasswordResetUser(userId, userName, userEmail);
                            $(this).toggleClass('selected');
                        });
                    } else {
                        $results.html('<p class="vigilante-no-results">' + (vigilanteAdmin.strings.noUsersFoundSearch || 'No users found') + '</p>').show();
                    }
                }
            });
        },

        /**
         * Toggle user selection for password reset
         */
        togglePasswordResetUser: function(userId, userName, userEmail) {
            var index = this.selectedPasswordResetUsers.indexOf(userId);
            var $selectedContainer = $('#vigilante-password-reset-selected');
            var $list = $selectedContainer.find('.vigilante-selected-users-list');
            var $btn = $('#vigilante-reset-selected-users');

            if (index === -1) {
                // Add user
                this.selectedPasswordResetUsers.push(userId);
                $list.append(
                    '<li data-user-id="' + userId + '">' +
                    '<span>' + this.escapeHtml(userName) + '</span>' +
                    '<button type="button" class="vigilante-remove-user" title="Remove">&times;</button>' +
                    '</li>'
                );
            } else {
                // Remove user
                this.selectedPasswordResetUsers.splice(index, 1);
                $list.find('li[data-user-id="' + userId + '"]').remove();
            }

            // Update UI
            if (this.selectedPasswordResetUsers.length > 0) {
                $selectedContainer.show();
                $btn.prop('disabled', false);
            } else {
                $selectedContainer.hide();
                $btn.prop('disabled', true);
            }

            // Handle remove button click
            $list.find('.vigilante-remove-user').off('click').on('click', function() {
                var uid = $(this).closest('li').data('user-id');
                var idx = Vigilante_Admin.selectedPasswordResetUsers.indexOf(uid);
                if (idx !== -1) {
                    Vigilante_Admin.selectedPasswordResetUsers.splice(idx, 1);
                }
                $(this).closest('li').remove();
                $('#vigilante-password-reset-results').find('li[data-user-id="' + uid + '"]').removeClass('selected');
                
                if (Vigilante_Admin.selectedPasswordResetUsers.length === 0) {
                    $selectedContainer.hide();
                    $btn.prop('disabled', true);
                }
            });
        },

        /**
         * Force reset for selected users
         */
        forceResetSelectedUsers: function() {
            var self = this;

            if (this.selectedPasswordResetUsers.length === 0) {
                return;
            }

            var currentUserId = parseInt(vigilanteAdmin.currentUserId || 0);
            var resettingSelf = this.selectedPasswordResetUsers.indexOf(currentUserId) !== -1;

            var confirmMsg = (vigilanteAdmin.strings.confirmForceReset || 'Force password reset for %d user(s)? A password reset email will be sent to each user.').replace('%d', this.selectedPasswordResetUsers.length);
            if (resettingSelf) {
                confirmMsg += '\n\n' + (vigilanteAdmin.strings.warningResettingSelf || 'WARNING: You are including yourself. Your session will end and you will need to set a new password.');
            }

            if (!confirm(confirmMsg)) {
                return;
            }

            var $btn = $('#vigilante-reset-selected-users');
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_force_password_reset',
                    nonce: vigilanteAdmin.nonce,
                    user_ids: this.selectedPasswordResetUsers
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('success', response.data.message);
                        
                        // Clear selection
                        self.selectedPasswordResetUsers = [];
                        $('#vigilante-password-reset-selected').hide().find('.vigilante-selected-users-list').empty();
                        $('#vigilante-password-reset-search').val('');
                        $('#vigilante-password-reset-results').hide().empty();

                        // Reload if resetting self
                        if (response.data.resetting_self) {
                            setTimeout(function() {
                                window.location.href = vigilanteAdmin.logoutUrl || '/wp-login.php';
                            }, 2000);
                        } else {
                            setTimeout(function() {
                                location.reload();
                            }, 1500);
                        }
                    } else {
                        self.showNotice('error', response.data);
                    }
                },
                error: function() {
                    self.showNotice('error', vigilanteAdmin.strings.anErrorOccurred || 'An error occurred');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.forceResetSelected || 'Force Reset for Selected Users');
                }
            });
        },

        /**
         * Force reset for all users
         */
        forceResetAllUsers: function() {
            var self = this;
            var includeSelf = $('#vigilante-reset-all-include-self').is(':checked');

            var confirmMsg = vigilanteAdmin.strings.confirmForceResetAll || 'This will force ALL users to reset their password. All users will receive a password reset email. Are you sure you want to continue?';
            if (includeSelf) {
                confirmMsg += '\n\n' + (vigilanteAdmin.strings.warningResettingSelfAll || 'WARNING: You are including yourself. Your session will end immediately.');
            }

            if (!confirm(confirmMsg)) {
                return;
            }

            var $btn = $('#vigilante-reset-all-users');
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_force_password_reset_all',
                    nonce: vigilanteAdmin.nonce,
                    include_self: includeSelf ? 1 : 0
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('success', response.data.message);
                        
                        // Reload if resetting self
                        if (response.data.resetting_self) {
                            setTimeout(function() {
                                window.location.href = vigilanteAdmin.logoutUrl || '/wp-login.php';
                            }, 2000);
                        } else {
                            setTimeout(function() {
                                location.reload();
                            }, 1500);
                        }
                    } else {
                        self.showNotice('error', response.data);
                    }
                },
                error: function() {
                    self.showNotice('error', vigilanteAdmin.strings.anErrorOccurred || 'An error occurred');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.forceResetAll || 'Force Reset for ALL Users');
                }
            });
        },

        /**
         * Update role reset summary when checkboxes change
         */
        updateRoleResetSummary: function() {
            var totalCount = 0;
            var includesSelf = false;

            $('.vigilante-reset-role-checkbox:checked').each(function() {
                totalCount += parseInt($(this).data('count') || 0);
                if ($(this).closest('label').find('em').length > 0) {
                    includesSelf = true;
                }
            });

            var $summary = $('#vigilante-reset-role-summary');
            var $selfOption = $('#vigilante-reset-role-self-option');
            var $btn = $('#vigilante-reset-by-role');

            if (totalCount > 0) {
                $('#vigilante-reset-role-count').text(totalCount);
                $summary.show();
                $btn.prop('disabled', false);
            } else {
                $summary.hide();
                $btn.prop('disabled', true);
            }

            if (includesSelf) {
                $selfOption.show();
            } else {
                $selfOption.hide();
                $('#vigilante-reset-role-include-self').prop('checked', false);
            }
        },

        /**
         * Force reset for users with selected roles
         */
        forceResetByRoles: function() {
            var self = this;
            var roles = [];

            $('.vigilante-reset-role-checkbox:checked').each(function() {
                roles.push($(this).val());
            });

            if (roles.length === 0) {
                self.showNotice('error', vigilanteAdmin.strings.noRolesSelected || 'Please select at least one role.');
                return;
            }

            var totalCount = 0;
            $('.vigilante-reset-role-checkbox:checked').each(function() {
                totalCount += parseInt($(this).data('count') || 0);
            });

            var includeSelf = $('#vigilante-reset-role-include-self').is(':checked');

            var confirmMsg = (vigilanteAdmin.strings.confirmForceResetByRole || 'Force password reset for %d user(s) with the selected roles? A password reset email will be sent to each user.').replace('%d', totalCount);
            if (includeSelf) {
                confirmMsg += '\n\n' + (vigilanteAdmin.strings.warningResettingSelfAll || 'WARNING: You are including yourself. Your session will end immediately.');
            }

            if (!confirm(confirmMsg)) {
                return;
            }

            var $btn = $('#vigilante-reset-by-role');
            $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_force_password_reset_by_role',
                    nonce: vigilanteAdmin.nonce,
                    roles: roles,
                    include_self: includeSelf ? 1 : 0
                },
                success: function(response) {
                    if (response.success) {
                        self.showNotice('success', response.data.message);

                        // Clear role checkboxes
                        $('.vigilante-reset-role-checkbox').prop('checked', false);
                        self.updateRoleResetSummary();

                        if (response.data.resetting_self) {
                            setTimeout(function() {
                                window.location.href = vigilanteAdmin.logoutUrl || '/wp-login.php';
                            }, 2000);
                        } else {
                            setTimeout(function() {
                                location.reload();
                            }, 1500);
                        }
                    } else {
                        self.showNotice('error', response.data);
                    }
                },
                error: function() {
                    self.showNotice('error', vigilanteAdmin.strings.anErrorOccurred || 'An error occurred');
                },
                complete: function() {
                    $btn.prop('disabled', false).text(vigilanteAdmin.strings.forceResetByRole || 'Force Reset for Selected Roles');
                }
            });
        },

        /**
         * Initialize user approval handlers
         */
        initUserApproval: function() {
            var self = this;

            // Approve user
            $(document).on('click', '.vigilante-approve-user', function() {
                var $btn = $(this);
                var userId = $btn.data('user-id');
                var $row = $btn.closest('tr');

                if (!confirm(vigilanteAdmin.strings.confirmApprove || 'Approve this user?')) {
                    return;
                }

                $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_approve_user',
                        nonce: vigilanteAdmin.nonce,
                        user_id: userId
                    },
                    success: function(response) {
                        if (response.success) {
                            self.showNotice('success', response.data.message);
                            $row.fadeOut(400, function() {
                                $(this).remove();
                                self.updatePendingCount();
                            });
                        } else {
                            self.showNotice('error', response.data);
                            $btn.prop('disabled', false).text(vigilanteAdmin.strings.approve || 'Approve');
                        }
                    },
                    error: function() {
                        self.showNotice('error', vigilanteAdmin.strings.error);
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.approve || 'Approve');
                    }
                });
            });

            // Reject user
            $(document).on('click', '.vigilante-reject-user', function() {
                var $btn = $(this);
                var userId = $btn.data('user-id');
                var $row = $btn.closest('tr');

                var reason = prompt(vigilanteAdmin.strings.rejectReason || 'Enter rejection reason (optional):');
                if (reason === null) {
                    return; // Cancelled
                }

                $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_reject_user',
                        nonce: vigilanteAdmin.nonce,
                        user_id: userId,
                        reason: reason
                    },
                    success: function(response) {
                        if (response.success) {
                            self.showNotice('success', response.data.message);
                            $row.fadeOut(400, function() {
                                $(this).remove();
                                self.updatePendingCount();
                            });
                        } else {
                            self.showNotice('error', response.data);
                            $btn.prop('disabled', false).text(vigilanteAdmin.strings.reject || 'Reject');
                        }
                    },
                    error: function() {
                        self.showNotice('error', vigilanteAdmin.strings.error);
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.reject || 'Reject');
                    }
                });
            });
        },

        /**
         * Update pending users count badge
         */
        updatePendingCount: function() {
            var $badge = $('.vigilante-pending-users-section .vigilante-badge-warning');
            var $table = $('.vigilante-pending-users-table tbody tr');
            var count = $table.length;

            if (count === 0) {
                $badge.remove();
                $('.vigilante-pending-users-table').replaceWith(
                    '<div class="vigilante-no-lockouts">' +
                    '<span class="dashicons dashicons-yes-alt"></span>' +
                    '<p>' + (vigilanteAdmin.strings.noPending || 'No pending registrations.') + '</p>' +
                    '</div>'
                );
            } else {
                $badge.text(count);
            }
        },

        /**
         * Initialize session management handlers
         */
        initSessionManagement: function() {
            var self = this;
            var searchTimer = null;
            this.selectedSessionUserId = null;

            // Search users for session management
            $(document).on('input', '#vigilante-session-user-search', function() {
                var query = $(this).val();
                var $results = $('#vigilante-session-search-results');

                clearTimeout(searchTimer);

                if (query.length < 2) {
                    $results.hide().empty();
                    return;
                }

                searchTimer = setTimeout(function() {
                    $.ajax({
                        url: vigilanteAdmin.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'vigilante_search_users_password_reset',
                            nonce: vigilanteAdmin.nonce,
                            query: query
                        },
                        success: function(response) {
                            if (response.success && response.data.length > 0) {
                                var html = '<ul class="vigilante-user-search-list">';
                                $.each(response.data, function(i, user) {
                                    html += '<li data-user-id="' + user.ID + '">' +
                                        '<img src="' + user.avatar + '" class="vigilante-user-avatar" alt="">' +
                                        '<div class="vigilante-user-info">' +
                                        '<strong>' + self.escapeHtml(user.display_name) + '</strong><br>' +
                                        '<small>' + self.escapeHtml(user.user_email) + '</small>' +
                                        '</div>' +
                                        '</li>';
                                });
                                html += '</ul>';
                                $results.html(html).show();
                            } else {
                                $results.html('<p class="vigilante-no-results">' + (vigilanteAdmin.strings.noUsers || 'No users found') + '</p>').show();
                            }
                        }
                    });
                }, 300);
            });

            // Click handler for user selection in session search
            $(document).on('click', '#vigilante-session-search-results li', function() {
                var userId = $(this).data('user-id');
                var userName = $(this).find('strong').text();
                self.loadUserSessions(userId, userName);
                $('#vigilante-session-search-results').hide();
                $('#vigilante-session-user-search').val(userName);
            });

            // Revoke single session
            $(document).on('click', '.vigilante-revoke-session', function() {
                var $btn = $(this);
                var userId = $btn.attr('data-user-id');
                var token = $btn.attr('data-token');
                var $row = $btn.closest('tr');
                var $paginatedContainer = $btn.closest('.vigilante-paginated-section');

                // Fallback to row token if button token is invalid
                if (!token || token.length < 32) {
                    token = $row.attr('data-token');
                }

                if (!token || token.length < 32) {
                    self.showNotice('error', vigilanteAdmin.strings.error || 'Invalid session token');
                    return;
                }

                if (!confirm(vigilanteAdmin.strings.confirmRevoke || 'Revoke this session?')) {
                    return;
                }

                $btn.prop('disabled', true);

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_revoke_session',
                        nonce: vigilanteAdmin.nonce,
                        user_id: userId,
                        token: token
                    },
                    success: function(response) {
                        if (response.success) {
                            self.showNotice('success', response.data.message);
                            $row.fadeOut(400, function() {
                                $(this).remove();
                                if ($paginatedContainer.length) {
                                    Vigilante_Admin.refreshFilePagination($paginatedContainer);
                                }
                            });
                        } else {
                            self.showNotice('error', response.data);
                            $btn.prop('disabled', false);
                        }
                    },
                    error: function() {
                        self.showNotice('error', vigilanteAdmin.strings.error);
                        $btn.prop('disabled', false);
                    }
                });
            });

            // Revoke all other sessions (current user)
            $(document).on('click', '.vigilante-revoke-other-sessions', function() {
                var $btn = $(this);
                var userId = $btn.data('user-id');

                if (!confirm(vigilanteAdmin.strings.confirmRevokeAll || 'Revoke all other sessions?')) {
                    return;
                }

                $btn.prop('disabled', true).text(vigilanteAdmin.strings.processing || 'Processing...');

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_revoke_all_sessions',
                        nonce: vigilanteAdmin.nonce,
                        user_id: userId,
                        include_current: 0
                    },
                    success: function(response) {
                        if (response.success) {
                            self.showNotice('success', response.data.message);
                            setTimeout(function() {
                                location.reload();
                            }, 1000);
                        } else {
                            self.showNotice('error', response.data);
                        }
                    },
                    error: function() {
                        self.showNotice('error', vigilanteAdmin.strings.error);
                    },
                    complete: function() {
                        $btn.prop('disabled', false).text(vigilanteAdmin.strings.revokeOthers || 'Revoke All Other Sessions');
                    }
                });
            });

            // Revoke all sessions for a user (admin managing other users)
            $(document).on('click', '.vigilante-revoke-all-user-sessions', function() {
                var $btn = $(this);

                if (!self.selectedSessionUserId) {
                    return;
                }

                if (!confirm(vigilanteAdmin.strings.confirmRevokeAllUser || 'Revoke ALL sessions for this user? They will be logged out everywhere.')) {
                    return;
                }

                $btn.prop('disabled', true);

                $.ajax({
                    url: vigilanteAdmin.ajaxUrl,
                    type: 'POST',
                    data: {
                        action: 'vigilante_revoke_all_sessions',
                        nonce: vigilanteAdmin.nonce,
                        user_id: self.selectedSessionUserId,
                        include_current: 1
                    },
                    success: function(response) {
                        if (response.success) {
                            self.showNotice('success', response.data.message);
                            $('#vigilante-user-sessions-container').hide();
                            $('#vigilante-session-user-search').val('');
                        } else {
                            self.showNotice('error', response.data);
                        }
                    },
                    error: function() {
                        self.showNotice('error', vigilanteAdmin.strings.error);
                    },
                    complete: function() {
                        $btn.prop('disabled', false);
                    }
                });
            });
        },

        /**
         * Load sessions for a specific user
         */
        loadUserSessions: function(userId, userName) {
            var self = this;
            this.selectedSessionUserId = userId;
            var $container = $('#vigilante-user-sessions-container');
            var $list = $('#vigilante-user-sessions-list');

            $list.html('<tr><td colspan="4">' + (vigilanteAdmin.strings.loading || 'Loading...') + '</td></tr>');
            $container.show();
            $('#vigilante-sessions-user-name').text((vigilanteAdmin.strings.sessionsFor || 'Sessions for: ') + userName);

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_get_user_sessions',
                    nonce: vigilanteAdmin.nonce,
                    user_id: userId
                },
                success: function(response) {
                    if (response.success) {
                        var sessions = response.data.sessions;
                        if (sessions.length === 0) {
                            $list.html('<tr><td colspan="4">' + (vigilanteAdmin.strings.noSessions || 'No active sessions') + '</td></tr>');
                            return;
                        }

                        var html = '';
                        $.each(sessions, function(i, session) {
                            var loginTime = session.login ? self.timeAgo(session.login) : (vigilanteAdmin.strings.unknown || 'Unknown');
                            html += '<tr data-token="' + session.token_hash + '">' +
                                '<td>' + self.escapeHtml(session.browser) + '</td>' +
                                '<td><code>' + self.escapeHtml(session.ip) + '</code></td>' +
                                '<td>' + loginTime + '</td>' +
                                '<td>' +
                                '<button type="button" class="button button-small vigilante-revoke-session" ' +
                                'data-user-id="' + userId + '" data-token="' + session.token_hash + '">' +
                                (vigilanteAdmin.strings.revoke || 'Revoke') +
                                '</button>' +
                                '</td>' +
                                '</tr>';
                        });
                        $list.html(html);
                    } else {
                        $list.html('<tr><td colspan="4">' + response.data + '</td></tr>');
                    }
                },
                error: function() {
                    $list.html('<tr><td colspan="4">' + vigilanteAdmin.strings.error + '</td></tr>');
                }
            });
        },

        /**
         * Format timestamp as time ago
         */
        timeAgo: function(timestamp) {
            var seconds = Math.floor((Date.now() / 1000) - timestamp);
            var s = vigilanteAdmin.strings;
            var intervals = [
                { label: s.timeYear || 'year', labelPlural: s.timeYears || 'years', seconds: 31536000 },
                { label: s.timeMonth || 'month', labelPlural: s.timeMonths || 'months', seconds: 2592000 },
                { label: s.timeDay || 'day', labelPlural: s.timeDays || 'days', seconds: 86400 },
                { label: s.timeHour || 'hour', labelPlural: s.timeHours || 'hours', seconds: 3600 },
                { label: s.timeMinute || 'minute', labelPlural: s.timeMinutes || 'minutes', seconds: 60 }
            ];

            for (var i = 0; i < intervals.length; i++) {
                var count = Math.floor(seconds / intervals[i].seconds);
                if (count >= 1) {
                    var unit = count > 1 ? intervals[i].labelPlural : intervals[i].label;
                    return (s.timeAgo || '%1$d %2$s ago').replace('%1$d', count).replace('%2$s', unit);
                }
            }
            return s.justNow || 'Just now';
        }
    };

    /* ---------------------------------------------------------------------
     * Security Analyzer (Dashboard widget) — v2.1.0
     * ------------------------------------------------------------------ */

    var VigilanteAnalyzer = {

        $root: null,

        init: function() {
            this.$root = $('#vigilante-analyzer');
            if (!this.$root.length) {
                // Widget not present on this page — still run hash focus in case a fix link was followed.
                this.hashFocusFlash();
                return;
            }

            // Scan button — 2-phase AJAX.
            $(document).on('click', '#vigilante-analyzer-scan', this.handleScan.bind(this));

            // Expand/collapse detailed breakdown.
            $(document).on('click', '.vigilante-analyzer-toggle', this.handleToggleDetails.bind(this));

            // Save weekly cron + email toggle on change.
            $(document).on('change',
                '.vigilante-analyzer-weekly input[type="checkbox"]',
                this.handleSettingsChange.bind(this));

            // Pulse the row we landed on if we came from a fix link.
            this.hashFocusFlash();

            // Upgrade the server-rendered SVG (no-op if already correct).
            this.renderSparklineFromData();
        },

        /**
         * Kick off a scan. Phase 'fast' first for instant feedback, then 'slow' for remote checks.
         */
        handleScan: function(e) {
            e.preventDefault();
            if (this.isScanning) {
                return;
            }
            this.isScanning = true;

            var $btn = $('#vigilante-analyzer-scan');
            var originalHtml = $btn.html();
            $btn.data('original-html', originalHtml);
            $btn.prop('disabled', true)
                .html('<span class="dashicons dashicons-update vigilante-analyzer-spin"></span> '
                    + (vigilanteAdmin.strings.analyzerFastPhase || 'Running fast checks…'));

            var self = this;

            // Expand the details section so the user sees results pour in.
            this.expandDetails(true);

            this.runScanPhase('fast')
                .done(function(fastReport) {
                    self.applyReport(fastReport);
                    $btn.html('<span class="dashicons dashicons-update vigilante-analyzer-spin"></span> '
                        + (vigilanteAdmin.strings.analyzerSlowPhase || 'Running remote checks…'));

                    self.runScanPhase('slow')
                        .done(function(slowReport) {
                            self.applyReport(slowReport);
                            if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                                Vigilante_Admin.showNotice('success',
                                    vigilanteAdmin.strings.analyzerScanComplete || 'Security scan complete.');
                            }
                        })
                        .fail(function(msg) {
                            if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                                Vigilante_Admin.showNotice('error',
                                    msg || vigilanteAdmin.strings.analyzerScanFailed || 'Security scan failed.');
                            }
                        })
                        .always(function() {
                            $btn.prop('disabled', false).html($btn.data('original-html') || originalHtml);
                            self.isScanning = false;
                        });
                })
                .fail(function(msg) {
                    $btn.prop('disabled', false).html($btn.data('original-html') || originalHtml);
                    self.isScanning = false;
                    if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                        Vigilante_Admin.showNotice('error',
                            msg || vigilanteAdmin.strings.analyzerScanFailed || 'Security scan failed.');
                    }
                });
        },

        runScanPhase: function(phase) {
            var deferred = $.Deferred();
            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                timeout: 60000,
                data: {
                    action: 'vigilante_analyzer_run',
                    nonce: vigilanteAdmin.nonce,
                    phase: phase
                }
            }).done(function(response) {
                if (response && response.success) {
                    deferred.resolve(response.data);
                } else {
                    deferred.reject(response && response.data ? response.data : null);
                }
            }).fail(function(xhr, status, err) {
                deferred.reject(err || status);
            });
            return deferred.promise();
        },

        /**
         * Map a 0-100 score percentage to a quality tag {label, slug}, mirroring
         * Vigilante_Admin::analyzer_quality_tag() in PHP.
         */
        qualityTag: function(pct) {
            pct = Math.max(0, Math.min(100, parseInt(pct, 10) || 0));
            var s = vigilanteAdmin.strings || {};
            // "Excellent" is reserved for a perfect score — a single missing point drops to Good.
            if (pct === 100) { return { label: s.analyzerQualityExcellent || 'Excellent', slug: 'a' }; }
            if (pct >= 70)   { return { label: s.analyzerQualityGood      || 'Good',      slug: 'b' }; }
            if (pct >= 50)   { return { label: s.analyzerQualityFair      || 'Fair',      slug: 'c' }; }
            if (pct >= 30)   { return { label: s.analyzerQualityPoor      || 'Poor',      slug: 'd' }; }
            return { label: s.analyzerQualityCritical || 'Critical', slug: 'e' };
        },

        /**
         * Swap a {a,b,c,d,e} slug modifier class on an element.
         */
        setQualityClass: function($el, baseClass, slug) {
            $el.removeClass(function(i, cls) {
                return (cls.match(new RegExp('(^|\\s)' + baseClass + '-[abcde](?=\\s|$)', 'g')) || []).join(' ');
            });
            $el.addClass(baseClass + '-' + slug);
        },

        /**
         * Merge a phase report into the widget DOM.
         */
        applyReport: function(report) {
            if (!report || typeof report !== 'object') {
                return;
            }
            var $root = this.$root;
            var self  = this;

            // Overall pass/warn/fail counts (summary).
            if (report.counts && typeof report.counts === 'object') {
                $root.find('[data-role="pass"]').text(report.counts.pass || 0);
                $root.find('[data-role="warn"]').text(report.counts.warn || 0);
                $root.find('[data-role="fail"]').text(report.counts.fail || 0);
            }

            // Main score circle + quality tag.
            if (report.grade) {
                var $card   = $root.find('.vigilante-analyzer-score-card');
                var $circle = $card.find('.vigilante-score-circle');
                var gradeLc = String(report.grade).toLowerCase();
                var scoreN  = parseInt(report.score, 10) || 0;

                if (!$circle.length || $circle.hasClass('vigilante-grade-empty')) {
                    $circle.remove();
                    $card.prepend(
                        '<div class="vigilante-score-circle vigilante-grade-'
                        + this.escAttr(gradeLc)
                        + '">'
                        + '<span class="vigilante-grade">' + this.esc(report.grade) + '</span>'
                        + '<span class="vigilante-score-text">' + this.esc(scoreN) + '%</span>'
                        + '</div>'
                    );
                } else {
                    $circle.removeClass(function(i, cls) {
                        return (cls.match(/(^|\s)vigilante-grade-\S+/g) || []).join(' ');
                    }).addClass('vigilante-grade-' + gradeLc);
                    $circle.find('.vigilante-grade').text(report.grade);
                    $circle.find('.vigilante-score-text').text(scoreN + '%');
                }

                // Quality tag in the score card.
                var quality = this.qualityTag(scoreN);
                var $tag    = $root.find('[data-role="quality-tag"]');
                if ($tag.length) {
                    this.setQualityClass($tag, 'vigilante-analyzer-quality', quality.slug);
                    $tag.text(quality.label);
                }
            }

            // "Last scan" label in the header.
            if (report.ran_at) {
                var $ranAt   = $root.find('[data-role="ran-at"]');
                var justNow  = vigilanteAdmin.strings.analyzerLastScanJustNow
                    || 'Last scan just now';
                $ranAt.html(
                    '<span class="dashicons dashicons-clock" aria-hidden="true"></span>'
                    + this.esc(justNow)
                );
            }

            // Per-category rows: quality pill, state counts, score, bar, and check rows.
            if (report.categories && typeof report.categories === 'object') {
                $.each(report.categories, function(slug, cat) {
                    var $cat = $root.find('.vigilante-analyzer-category[data-category="' + slug + '"]');
                    if (!$cat.length) {
                        return;
                    }

                    var infoOnly = $cat.attr('data-info-only') === '1';
                    var counts   = (cat.counts && typeof cat.counts === 'object') ? cat.counts : {};

                    if (!infoOnly) {
                        var earned = parseInt(cat.earned, 10) || 0;
                        var max    = parseInt(cat.max, 10) || 0;
                        var pct    = max > 0 ? Math.round((earned / max) * 100) : 0;
                        var cq     = self.qualityTag(pct);

                        $cat.find('[data-role="earned"]').text(earned);

                        var $catQuality = $cat.find('[data-role="category-quality"]');
                        if ($catQuality.length) {
                            self.setQualityClass($catQuality, 'vigilante-analyzer-quality', cq.slug);
                            // Update only the label span; the pill also contains the
                            // "X/Y tests" counter so a blanket .text() would wipe it.
                            var $label = $catQuality.find('[data-role="category-quality-label"]');
                            if ($label.length) {
                                $label.text(cq.label);
                            } else {
                                $catQuality.text(cq.label);
                            }
                        }

                        // "X/Y tests" inside the pill. Total is everything that
                        // scores (pass + warn + fail), info/skip are excluded
                        // because they don't move the category score.
                        var $tests = $cat.find('[data-role="category-tests"]');
                        if ($tests.length) {
                            var passed = parseInt(counts.pass, 10) || 0;
                            var total  = passed
                                       + (parseInt(counts.warn, 10) || 0)
                                       + (parseInt(counts.fail, 10) || 0);
                            var tpl = (vigilanteAdmin.strings && vigilanteAdmin.strings.testsCounter)
                                      || '%1$d/%2$d tests';
                            $tests.text(tpl.replace('%1$d', passed).replace('%2$d', total));
                            $tests.attr('data-passed', passed);
                            $tests.attr('data-total', total);
                        }

                        // Progress bar (width + quality color).
                        var $bar = $cat.find('[data-role="category-bar"]');
                        if ($bar.length) {
                            $bar.css('width', pct + '%');
                            self.setQualityClass($bar, 'vigilante-analyzer-category-bar-fill', cq.slug);
                        }
                    }

                    // State counts — show each chip only when count > 0.
                    // Info-only categories (like reputation) also show an info count.
                    self.updateCategoryState($cat, 'pass', parseInt(counts.pass, 10) || 0);
                    self.updateCategoryState($cat, 'warn', parseInt(counts.warn, 10) || 0);
                    self.updateCategoryState($cat, 'fail', parseInt(counts.fail, 10) || 0);
                    if (infoOnly) {
                        self.updateCategoryState($cat, 'info', parseInt(counts.info, 10) || 0);
                        // Info-only categories replace the progress bar with a status pill
                        // ("All clear" when nothing actionable, "N findings" otherwise).
                        self.updateInfoStatus($cat, counts);
                    }

                    // Replace the check rows only for checks this phase actually returned.
                    if (cat.checks && cat.checks.length) {
                        var $list = $cat.find('[data-role="check-list"]');
                        $list.find('.vigilante-analyzer-check-empty').remove();

                        $.each(cat.checks, function(i, check) {
                            var $existing = $list.find('[data-check-id="' + check.id + '"]');
                            var html = self.renderCheckRow(check);
                            if ($existing.length) {
                                $existing.replaceWith(html);
                            } else {
                                $list.append(html);
                            }
                        });
                    }
                });
            }
        },

        /**
         * Update a per-category state chip (pass/warn/fail). Adds the chip if it doesn't
         * exist yet, updates its number, or removes it when the count is zero.
         */
        updateCategoryState: function($cat, state, count) {
            var $wrap = $cat.find('[data-role="category-states"]');
            if (!$wrap.length) {
                return;
            }
            var selector = '.vigilante-analyzer-category-state--' + state;
            var $chip    = $wrap.find(selector);

            if (count > 0) {
                if (!$chip.length) {
                    var iconMap = { pass: 'yes', warn: 'warning', fail: 'no', info: 'info-outline' };
                    var titleMap = {
                        pass: 'Passing',
                        warn: 'Warning',
                        fail: 'Failing',
                        info: 'Informational'
                    };
                    var title = titleMap[state] || '';
                    $chip = $(
                        '<span class="vigilante-analyzer-category-state vigilante-analyzer-category-state--'
                        + state + '" title="' + this.escAttr(title) + '">'
                        + '<span data-role="state-' + state + '">0</span>'
                        + '<span class="dashicons dashicons-' + iconMap[state] + '" aria-hidden="true"></span>'
                        + '</span>'
                    );
                    // Keep order: pass → warn → fail → info.
                    if (state === 'pass') {
                        $wrap.prepend($chip);
                    } else if (state === 'warn') {
                        var $passChip = $wrap.find('.vigilante-analyzer-category-state--pass');
                        if ($passChip.length) { $chip.insertAfter($passChip); } else { $wrap.prepend($chip); }
                    } else if (state === 'fail') {
                        var $infoChip = $wrap.find('.vigilante-analyzer-category-state--info');
                        if ($infoChip.length) { $chip.insertBefore($infoChip); } else { $wrap.append($chip); }
                    } else {
                        $wrap.append($chip);
                    }
                }
                $chip.find('[data-role="state-' + state + '"]').text(count);
            } else if ($chip.length) {
                $chip.remove();
            }
        },

        /**
         * Refresh the "All clear" / "N findings" pill for an info-only category.
         * Runs after a scan replaces the counts on the server side.
         */
        updateInfoStatus: function($cat, counts) {
            var $status = $cat.find('[data-role="info-status"]');
            if (!$status.length) {
                return;
            }
            var warnN  = parseInt(counts.warn, 10) || 0;
            var failN  = parseInt(counts.fail, 10) || 0;
            var issues = warnN + failN;
            var strings = (vigilanteAdmin && vigilanteAdmin.strings) || {};

            if (issues > 0) {
                var template = strings.analyzerInfoFindings || '%d findings';
                var label    = template.replace('%d', issues);
                $status
                    .removeClass('vigilante-analyzer-category-status--clear')
                    .addClass('vigilante-analyzer-category-status--attention')
                    .html(
                        '<span class="dashicons dashicons-warning" aria-hidden="true"></span>'
                        + this.esc(label)
                    );
            } else {
                var clear = strings.analyzerInfoAllClear || 'All clear';
                $status
                    .removeClass('vigilante-analyzer-category-status--attention')
                    .addClass('vigilante-analyzer-category-status--clear')
                    .html(
                        '<span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>'
                        + this.esc(clear)
                    );
            }
        },

        renderCheckRow: function(check) {
            var state = check.state || 'skip';
            var icons = {
                pass: 'yes-alt',
                warn: 'warning',
                fail: 'dismiss',
                info: 'info',
                skip: 'minus'
            };
            var icon = icons[state] || 'minus';

            var scoreHtml = '';
            var max = parseInt(check.max, 10) || 0;
            if (max > 0 && state !== 'info' && state !== 'skip') {
                scoreHtml = '<span class="vigilante-analyzer-check-score">'
                    + this.esc((parseInt(check.score, 10) || 0) + '/' + max)
                    + '</span>';
            }

            var fixHtml = '';
            if (check.fix_link && (state === 'fail' || state === 'warn')) {
                fixHtml = '<a href="' + this.escAttr(check.fix_link) + '" class="vigilante-analyzer-fix-link">'
                    + this.esc(vigilanteAdmin.strings.analyzerGoToSetting || 'Go to setting')
                    + '<span class="vigilante-analyzer-fix-arrow" aria-hidden="true">&rarr;</span></a>';
            } else if (check.fix_link && state === 'info') {
                var isExt = /^https?:\/\//i.test(check.fix_link);
                fixHtml = '<a href="' + this.escAttr(check.fix_link) + '" class="vigilante-analyzer-fix-link"'
                    + (isExt ? ' target="_blank" rel="noopener noreferrer"' : '') + '>'
                    + this.esc(vigilanteAdmin.strings.analyzerLearnMore || 'Learn more')
                    + '<span class="vigilante-analyzer-fix-arrow" aria-hidden="true">&rarr;</span></a>';
            }

            var detailHtml = '';
            if (check.detail) {
                detailHtml = '<p class="vigilante-analyzer-check-detail">' + this.esc(check.detail) + '</p>';
            }

            return '<li class="vigilante-analyzer-check vigilante-analyzer-check--' + this.escAttr(state) + '"'
                + ' data-check-id="' + this.escAttr(check.id || '') + '">'
                + '<span class="vigilante-analyzer-check-icon dashicons dashicons-' + this.escAttr(icon) + '" aria-hidden="true"></span>'
                + '<div class="vigilante-analyzer-check-body">'
                + '<div class="vigilante-analyzer-check-label">'
                + '<span>' + this.esc(check.label || '') + '</span>'
                + scoreHtml
                + '</div>'
                + detailHtml
                + fixHtml
                + '</div>'
                + '</li>';
        },

        /**
         * Expand or collapse the detailed breakdown section.
         */
        handleToggleDetails: function(e) {
            e.preventDefault();
            var $btn = $(e.currentTarget);
            var expanded = $btn.attr('aria-expanded') === 'true';
            this.expandDetails(!expanded);
        },

        expandDetails: function(expand) {
            var $btn = this.$root.find('.vigilante-analyzer-toggle');
            var $details = this.$root.find('.vigilante-analyzer-details');
            var show = !!expand;

            $btn.attr('aria-expanded', show ? 'true' : 'false');

            var label = show
                ? (vigilanteAdmin.strings.analyzerHideDetails || 'Hide detailed breakdown')
                : (vigilanteAdmin.strings.analyzerShowDetails || 'Show detailed breakdown');

            // Preserve the chevron element; only swap the label text.
            var $chevron = $btn.find('.vigilante-analyzer-toggle-chevron').detach();
            if (!$chevron.length) {
                $chevron = $('<span class="vigilante-analyzer-toggle-chevron" aria-hidden="true"></span>');
            }
            $btn.text(label).append(' ').append($chevron);

            if (show) {
                $details.removeAttr('hidden');
            } else {
                $details.attr('hidden', 'hidden');
            }
        },

        /**
         * Auto-save weekly scan + email toggles.
         */
        handleSettingsChange: function(e) {
            var $input = $(e.currentTarget);
            var $weekly = this.$root.find('input[name="security_analyzer[weekly_scan_enabled]"]');
            var $email = this.$root.find('input[name="security_analyzer[email_on_regression]"]');

            $.ajax({
                url: vigilanteAdmin.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'vigilante_analyzer_save_settings',
                    nonce: vigilanteAdmin.nonce,
                    weekly_scan_enabled: $weekly.is(':checked') ? 1 : 0,
                    email_on_regression: $email.is(':checked') ? 1 : 0
                },
                success: function(response) {
                    if (response && response.success) {
                        if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                            Vigilante_Admin.showNotice('success',
                                vigilanteAdmin.strings.analyzerSettingsSaved || 'Analyzer settings saved.');
                        }
                    } else {
                        if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                            Vigilante_Admin.showNotice('error',
                                (response && response.data) || vigilanteAdmin.strings.error);
                        }
                        $input.prop('checked', !$input.is(':checked'));
                    }
                },
                error: function() {
                    if (typeof Vigilante_Admin !== 'undefined' && Vigilante_Admin.showNotice) {
                        Vigilante_Admin.showNotice('error', vigilanteAdmin.strings.error);
                    }
                    $input.prop('checked', !$input.is(':checked'));
                }
            });
        },

        /**
         * Re-render the sparkline from data-points (no-op if no points).
         */
        renderSparklineFromData: function() {
            var $wrap = this.$root.find('[data-role="sparkline"]');
            if (!$wrap.length) {
                return;
            }
            var raw = $wrap.attr('data-points');
            if (!raw) {
                return;
            }
            try {
                var points = JSON.parse(raw);
                if (!points || points.length < 2) {
                    return;
                }
                // Only regenerate if the SVG is missing (e.g. server gave empty markup).
                if (!$wrap.find('svg').length) {
                    $wrap.html(this.buildSparklineSvg(points));
                }
                this.attachSparklineHotspots($wrap, points);
            } catch (err) { /* ignore parse errors */ }
        },

        /**
         * Inject invisible hot-spots over each sparkline point and wire up a tooltip
         * that shows the score on hover/focus.
         */
        attachSparklineHotspots: function($wrap, points) {
            if (!points || points.length < 2) {
                return;
            }
            // Idempotent: clear any previous hot-spots/tooltip first.
            $wrap.find('.vigilante-analyzer-sparkline-dot, .vigilante-analyzer-sparkline-tooltip').remove();

            var SVG_W = 280, SVG_H = 60, PAD = 4;
            var usableW = SVG_W - PAD * 2;
            var usableH = SVG_H - PAD * 2;
            var step = usableW / Math.max(1, points.length - 1);
            var max = 100;

            var $tooltip = $('<div class="vigilante-analyzer-sparkline-tooltip" aria-hidden="true"></div>');
            $wrap.append($tooltip);

            for (var i = 0; i < points.length; i++) {
                var x = PAD + (i * step);
                var y = PAD + (usableH - ((points[i] / max) * usableH));
                var xPct = (x / SVG_W) * 100;
                var yPct = (y / SVG_H) * 100;

                var $dot = $('<button type="button" class="vigilante-analyzer-sparkline-dot"></button>')
                    .css({ left: xPct + '%', top: yPct + '%' })
                    .attr('data-score', points[i])
                    .attr('data-index', i)
                    .attr('aria-label', String(points[i]));
                $wrap.append($dot);
            }

            $wrap.off('.vigSpark');
            $wrap.on('mouseenter.vigSpark focus.vigSpark', '.vigilante-analyzer-sparkline-dot', function() {
                var $dot = $(this);
                $tooltip
                    .text($dot.attr('data-score'))
                    .css({ left: $dot.css('left'), top: $dot.css('top') })
                    .addClass('is-visible');
            });
            $wrap.on('mouseleave.vigSpark blur.vigSpark', '.vigilante-analyzer-sparkline-dot', function() {
                $tooltip.removeClass('is-visible');
            });
        },

        buildSparklineSvg: function(points) {
            var width = 280;
            var height = 60;
            var padding = 4;
            var usableW = width - (padding * 2);
            var usableH = height - (padding * 2);
            var count = points.length;
            var step = usableW / Math.max(1, count - 1);
            var max = 100;

            var coords = [];
            for (var i = 0; i < count; i++) {
                var x = padding + (i * step);
                var y = padding + (usableH - ((points[i] / max) * usableH));
                coords.push(x.toFixed(2) + ',' + y.toFixed(2));
            }
            var path = 'M ' + coords.join(' L ');
            var lastX = padding + ((count - 1) * step);
            var lastY = padding + (usableH - ((points[count - 1] / max) * usableH));

            return '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none" '
                + 'role="img" focusable="false">'
                + '<path d="' + path + '" fill="none" stroke="currentColor" '
                + 'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
                + '<circle cx="' + lastX.toFixed(2) + '" cy="' + lastY.toFixed(2) + '" r="3" fill="currentColor"/>'
                + '</svg>';
        },

        /**
         * When landing on a fix link (#field-* or #vigilante-section-*),
         * scroll smoothly and flash-highlight the target.
         */
        hashFocusFlash: function() {
            var hash = window.location.hash;
            if (!hash || hash.length < 2) {
                return;
            }
            // Accept both section anchors and field anchors.
            if (!/^#(?:field-|vigilante-section-)/.test(hash)) {
                return;
            }

            setTimeout(function() {
                var $target;
                try {
                    $target = $(hash);
                } catch (err) { return; }
                if (!$target || !$target.length) {
                    return;
                }

                // Scroll to it smoothly.
                if ('scrollIntoView' in $target[0]) {
                    $target[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
                }

                // Flash — remove any previous flash first.
                $('.vigilante-focus-flash').removeClass('vigilante-focus-flash');
                $target.addClass('vigilante-focus-flash');
                setTimeout(function() {
                    $target.removeClass('vigilante-focus-flash');
                }, 1800);
            }, 150);
        },

        /** Escape text for HTML. */
        esc: function(str) {
            return String(str == null ? '' : str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },

        /** Escape text for HTML attribute. */
        escAttr: function(str) {
            return this.esc(str);
        }
    };

    // Initialize on document ready
    $(document).ready(function() {
        Vigilante_Admin.init();
        Vigilante_Admin.initPasswordReset();
        Vigilante_Admin.initUserApproval();
        Vigilante_Admin.initSessionManagement();
        VigilanteAnalyzer.init();
    });

})(jQuery);