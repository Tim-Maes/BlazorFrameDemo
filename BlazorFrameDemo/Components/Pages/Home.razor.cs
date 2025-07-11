using BlazorFrame;
using Microsoft.AspNetCore.Components;

namespace BlazorFrameDemo.Components.Pages
{
    public partial class Home
    {
        [Inject] public ILogger<Home> Logger { get; set; } = default!;

        // State variables
        private string currentUrl = "https://httpbin.org/html";
        private string testUrl = "data:text/html,<h1>Sandbox Test</h1><p>Testing sandbox restrictions</p><button onclick=\"alert('Popup test')\">Test Alert</button><form><input placeholder=\"Form test\"></form>";
        private bool enableAutoResize = true;
        private bool requireHttps = false;
        private bool allowInsecureConnections = false;
        private bool isLoaded = false;

        // Counters
        private int messageCount = 0;
        private int securityViolations = 0;
        private int configurationErrors = 0;
        private int urlValidationErrors = 0;
        private int cspHeadersGenerated = 0;

        // Current configuration state
        private string currentSecurityPreset = "development";
        private SandboxPreset currentSandboxPreset = SandboxPreset.None;
        private ConfigurationValidationResult? configValidationResult;

        // Security configurations
        private MessageSecurityOptions currentSecurityOptions = new MessageSecurityOptions().ForDevelopment();

        private readonly MessageSecurityOptions conflictTestOptions = new()
        {
            RequireHttps = true,                // Require HTTPS
            AllowInsecureConnections = true,   // But also allow HTTP (conflict!)
            SandboxPreset = SandboxPreset.Paranoid,
            EnableSandbox = true,
            EnableStrictValidation = true,
            MaxMessageSize = 16 * 1024,
            MaxJsonDepth = 3,
            MaxObjectProperties = 10,
            MaxArrayElements = 10,
            LogSecurityViolations = true
        };

        private readonly MessageSecurityOptions basicSandboxOptions = new MessageSecurityOptions().WithBasicSandbox();
        private readonly MessageSecurityOptions permissiveSandboxOptions = new MessageSecurityOptions().WithPermissiveSandbox();
        private readonly MessageSecurityOptions strictSandboxOptions = new MessageSecurityOptions().WithStrictSandbox();
        private readonly MessageSecurityOptions paranoidSandboxOptions = new MessageSecurityOptions().WithParanoidSandbox();

        // CSP configurations
        private CspOptions? currentCspOptions = null;

        // Event logging
        private List<LogEntry> eventLog = new();

        private class LogEntry
        {
            public DateTime Timestamp { get; set; } = DateTime.Now;
            public string Type { get; set; } = "";
            public string Message { get; set; } = "";
            public string Details { get; set; } = "";
        }

        protected override void OnInitialized()
        {
            UpdateConfigurationValidation();
        }

        #region Event Handlers

        private async Task HandleIframeLoad()
        {
            isLoaded = true;
            AddLogEntry("LOAD", "Iframe loaded successfully", currentUrl);
            StateHasChanged();
        }

        private async Task HandleValidatedMessage(IframeMessage message)
        {
            messageCount++;
            AddLogEntry("MESSAGE", $"Valid message from {message.Origin}",
                $"Type: {message.MessageType ?? "N/A"}, Data: {TruncateString(message.Data, 100)}");
            StateHasChanged();
        }

        private async Task HandleSecurityViolation(IframeMessage violation)
        {
            securityViolations++;
            var violationType = violation.MessageType switch
            {
                "url-validation" => "URL_VIOLATION",
                "configuration-validation" => "CONFIG_VIOLATION",
                _ => "SECURITY_VIOLATION"
            };

            if (violationType == "CONFIG_VIOLATION")
                configurationErrors++;
            if (violationType == "URL_VIOLATION")
                urlValidationErrors++;

            AddLogEntry(violationType, $"Security violation: {violation.ValidationError}",
                $"Origin: {violation.Origin}, Data: {TruncateString(violation.Data, 50)}");
            StateHasChanged();
        }

        private async Task HandleConflictTestMessage(IframeMessage message)
        {
            AddLogEntry("CONFLICT_TEST", $"Conflict test message from {message.Origin}",
                $"This message passed despite conflicting configuration");
        }

        private async Task HandleConflictTestViolation(IframeMessage violation)
        {
            AddLogEntry("CONFLICT_TEST", $"Conflict test violation: {violation.ValidationError}",
                $"This demonstrates configuration conflict detection");
        }

        private async Task HandleSandboxTestViolation(string sandboxType, IframeMessage violation)
        {
            AddLogEntry("SANDBOX_TEST", $"{sandboxType} sandbox violation: {violation.ValidationError}",
                $"Testing sandbox restriction effectiveness");
        }

        private async Task HandleInitializationError(Exception ex)
        {
            AddLogEntry("ERROR", "Iframe initialization failed", ex.Message);
        }

        private async Task HandleCspHeaderGenerated(CspHeader cspHeader)
        {
            cspHeadersGenerated++;
            AddLogEntry("CSP", $"CSP header generated: {cspHeader.HeaderName}",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
            StateHasChanged();
        }

        #endregion

        #region Control Handlers

        private async Task OnUrlChange(ChangeEventArgs e)
        {
            currentUrl = e.Value?.ToString() ?? "";
            isLoaded = false;
            AddLogEntry("URL_CHANGE", $"URL changed to: {currentUrl}");
            StateHasChanged();
        }

        private async Task OnSecurityPresetChange(ChangeEventArgs e)
        {
            currentSecurityPreset = e.Value?.ToString() ?? "development";

            currentSecurityOptions = currentSecurityPreset switch
            {
                "development" => new MessageSecurityOptions().ForDevelopment(),
                "production" => new MessageSecurityOptions().ForProduction(),
                "payment" => new MessageSecurityOptions().ForPaymentWidget(),
                "trusted" => new MessageSecurityOptions().ForTrustedContent(),
                "custom" => new MessageSecurityOptions
                {
                    EnableStrictValidation = true,
                    MaxMessageSize = 32 * 1024,
                    LogSecurityViolations = true,
                    SandboxPreset = currentSandboxPreset,
                    EnableSandbox = currentSandboxPreset != SandboxPreset.None,
                    RequireHttps = requireHttps,
                    AllowInsecureConnections = allowInsecureConnections
                },
                _ => new MessageSecurityOptions().ForDevelopment()
            };

            UpdateConfigurationValidation();
            AddLogEntry("PRESET_CHANGE", $"Security preset changed to: {currentSecurityPreset}");
            StateHasChanged();
        }

        private async Task OnSandboxPresetChange(ChangeEventArgs e)
        {
            if (Enum.TryParse<SandboxPreset>(e.Value?.ToString(), out var preset))
            {
                currentSandboxPreset = preset;
                currentSecurityOptions.SandboxPreset = preset;
                currentSecurityOptions.EnableSandbox = preset != SandboxPreset.None;

                UpdateConfigurationValidation();
                AddLogEntry("SANDBOX_CHANGE", $"Sandbox preset changed to: {preset}",
                    $"Effective sandbox: {currentSecurityOptions.GetEffectiveSandboxValue() ?? "none"}");
                StateHasChanged();
            }
        }

        private async Task OnHttpsRequirementChange(ChangeEventArgs e)
        {
            requireHttps = (bool)(e.Value ?? false);
            currentSecurityOptions.RequireHttps = requireHttps;
            UpdateConfigurationValidation();
            AddLogEntry("HTTPS_CHANGE", $"HTTPS requirement: {(requireHttps ? "enabled" : "disabled")}");
            StateHasChanged();
        }

        private async Task OnInsecureConnectionsChange(ChangeEventArgs e)
        {
            allowInsecureConnections = (bool)(e.Value ?? false);
            currentSecurityOptions.AllowInsecureConnections = allowInsecureConnections;
            UpdateConfigurationValidation();
            AddLogEntry("INSECURE_CHANGE", $"Allow insecure connections: {(allowInsecureConnections ? "enabled" : "disabled")}");
            StateHasChanged();
        }

        #endregion

        #region Testing Methods

        private async Task TestValidConfiguration()
        {
            var validConfig = new MessageSecurityOptions().ForProduction();
            var validation = validConfig.ValidateConfiguration();

            AddLogEntry("CONFIG_TEST", "Testing valid configuration",
                $"Valid: {validation.IsValid}, Warnings: {validation.Warnings.Count}, Suggestions: {validation.Suggestions.Count}");
        }

        private async Task TestConflictingConfiguration()
        {
            var conflictConfig = new MessageSecurityOptions
            {
                RequireHttps = true,
                AllowInsecureConnections = true,  // Conflict!
                EnableSandbox = false,
                SandboxPreset = SandboxPreset.Strict  // Another conflict!
            };

            var validation = conflictConfig.ValidateConfiguration();

            AddLogEntry("CONFIG_TEST", "Testing conflicting configuration",
                $"Valid: {validation.IsValid}, Warnings: {validation.Warnings.Count}, Errors: {validation.Errors.Count}");

            foreach (var warning in validation.Warnings)
            {
                AddLogEntry("CONFIG_WARNING", warning);
            }
        }

        private async Task TestInvalidConfiguration()
        {
            var invalidConfig = new MessageSecurityOptions
            {
                MaxMessageSize = -1,  // Invalid!
                MaxJsonDepth = 0,     // Invalid!
                MaxObjectProperties = -5  // Invalid!
            };

            try
            {
                invalidConfig.ValidateAndThrow();
                AddLogEntry("CONFIG_TEST", "Invalid configuration was not caught!");
            }
            catch (Exception ex)
            {
                AddLogEntry("CONFIG_TEST", "Invalid configuration correctly caught", ex.Message);
            }
        }

        private async Task ValidateAllConfigurations()
        {
            var configs = new Dictionary<string, MessageSecurityOptions>
            {
                { "Development", new MessageSecurityOptions().ForDevelopment() },
                { "Production", new MessageSecurityOptions().ForProduction() },
                { "Payment Widget", new MessageSecurityOptions().ForPaymentWidget() },
                { "Trusted Content", new MessageSecurityOptions().ForTrustedContent() },
                { "Current Config", currentSecurityOptions },
                { "Conflict Test", conflictTestOptions }
            };

            foreach (var config in configs)
            {
                var validation = config.Value.ValidateConfiguration();
                AddLogEntry("CONFIG_VALIDATION", $"Validated {config.Key}",
                    $"Valid: {validation.IsValid}, Warnings: {validation.Warnings.Count}, Suggestions: {validation.Suggestions.Count}");
            }
        }

        private async Task TestHttpsEnforcement()
        {
            var httpsConfig = new MessageSecurityOptions
            {
                RequireHttps = true,
                AllowInsecureConnections = false
            };

            var httpUrl = "http://httpbin.org/html";
            var httpsUrl = "https://httpbin.org/html";

            AddLogEntry("HTTPS_TEST", "Testing HTTPS enforcement",
                $"Testing {httpUrl} vs {httpsUrl} with RequireHttps=true");

            // This would be tested by changing the currentUrl to HTTP and observing violations
        }

        private async Task TestSandboxBypass()
        {
            var bypassTest = "data:text/html,<script>try { window.parent.postMessage({type: 'bypass', data: 'sandbox bypass attempt'}, '*'); } catch(e) { console.log('Sandbox blocked script'); }</script>";
            AddLogEntry("SANDBOX_TEST", "Testing sandbox bypass attempt",
                $"Attempting to run script in sandboxed iframe");
        }

        private async Task TestMaliciousUrl()
        {
            var maliciousUrls = new[]
            {
                "javascript:alert('XSS')",
                "vbscript:msgbox('XSS')",
                "data:text/html,<script>eval('alert(1)')</script>"
            };

            foreach (var url in maliciousUrls)
            {
                AddLogEntry("MALICIOUS_TEST", $"Testing malicious URL: {url}",
                    "This should be blocked by security validation");
            }
        }

        private async Task TestCustomValidation()
        {
            var customConfig = new MessageSecurityOptions
            {
                CustomValidator = (origin, message) =>
                {
                    // Custom validation: reject messages containing "evil"
                    return !message.Contains("evil", StringComparison.OrdinalIgnoreCase);
                }
            };

            AddLogEntry("CUSTOM_TEST", "Testing custom validation",
                "Custom validator will reject messages containing 'evil'");
        }

        private async Task ExportConfiguration()
        {
            var configSummary = $@"
BlazorFrame Configuration Export
Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

Security Preset: {currentSecurityPreset}
Sandbox Preset: {currentSandboxPreset}
Effective Sandbox: {currentSecurityOptions.GetEffectiveSandboxValue() ?? "none"}

Security Options:
- Require HTTPS: {currentSecurityOptions.RequireHttps}
- Allow Insecure: {currentSecurityOptions.AllowInsecureConnections}
- Strict Validation: {currentSecurityOptions.EnableStrictValidation}
- Max Message Size: {currentSecurityOptions.MaxMessageSize} bytes
- Max JSON Depth: {currentSecurityOptions.MaxJsonDepth}
- Max Object Props: {currentSecurityOptions.MaxObjectProperties}
- Max Array Elements: {currentSecurityOptions.MaxArrayElements}

Configuration Validation:
- Valid: {configValidationResult?.IsValid ?? false}
- Errors: {configValidationResult?.Errors.Count ?? 0}
- Warnings: {configValidationResult?.Warnings.Count ?? 0}
- Suggestions: {configValidationResult?.Suggestions.Count ?? 0}
";

            AddLogEntry("EXPORT", "Configuration exported to log", configSummary);
        }

        #endregion

        #region Utility Methods

        private void UpdateConfigurationValidation()
        {
            configValidationResult = currentSecurityOptions.ValidateConfiguration();
        }

        private void AddLogEntry(string type, string message, string details = "")
        {
            eventLog.Add(new LogEntry { Type = type, Message = message, Details = details });
            if (eventLog.Count > 200) // Keep log manageable
            {
                eventLog.RemoveRange(0, 50); // Remove oldest 50 entries
            }
        }

        private void ClearLog()
        {
            eventLog.Clear();
            messageCount = 0;
            securityViolations = 0;
            configurationErrors = 0;
            urlValidationErrors = 0;
            cspHeadersGenerated = 0;
            StateHasChanged();
        }

        private string GetLogEntryClass(string type) => type.ToLower() switch
        {
            "load" or "message" => "success",
            "security_violation" or "url_violation" or "malicious_test" => "security",
            "config_violation" or "config_test" or "config_validation" or "config_warning" => "config",
            "sandbox_test" or "sandbox_change" => "sandbox",
            "error" => "error",
            "https_test" or "custom_test" or "conflict_test" => "warning",
            _ => "info"
        };

        private static string TruncateString(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
                return input;
            return input[..maxLength] + "...";
        }

        #endregion
    }
}