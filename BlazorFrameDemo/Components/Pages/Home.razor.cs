using BlazorFrame;
using Microsoft.AspNetCore.Components;

namespace BlazorFrameDemo.Components.Pages
{
    public partial class Home
    {
        [Inject] public ILogger<Home> Logger { get; set; } = default!;

        // BlazorFrame component references
        private BlazorFrame.BlazorFrame? basicFrame;
        private BlazorFrame.BlazorFrame? fixedFrame;
        private BlazorFrame.BlazorFrame? securityFrame;

        // State variables
        private string currentUrl = "https://httpbin.org/html";
        private bool enableAutoResize = true;
        private bool isLoaded = false;
        private int messageCount = 0;
        private int securityViolations = 0;
        private int cspHeadersGenerated = 0;
        private string customMessage = """{"type": "custom", "data": "Hello World!"}""";
        private string currentCspMode = "none";
        private string lastGeneratedCspHeader = "";

        // Security configurations
        private MessageSecurityOptions currentSecurityOptions = new()
        {
            EnableStrictValidation = true,
            MaxMessageSize = 32 * 1024,
            LogSecurityViolations = true
        };

        private MessageSecurityOptions strictSecurityOptions = new()
        {
            EnableStrictValidation = true,
            MaxMessageSize = 16 * 1024,
            LogSecurityViolations = true,
            MaxJsonDepth = 5,
            MaxObjectProperties = 50,
            MaxArrayElements = 100
        };

        private List<string> restrictedOrigins = new() { "https://httpbin.org", "https://www.example.com" };

        // CSP configurations
        private CspOptions? currentCspOptions = null;

        private readonly CspOptions developmentCsp = new CspOptions()
            .ForDevelopment()
            .AllowFrameSources("https://httpbin.org", "https://www.example.com");

        private readonly CspOptions productionCsp = new CspOptions()
            .ForProduction()
            .AllowFrameSources("https://httpbin.org", "https://www.example.com")
            .WithScriptNonce("production-nonce-123");

        private readonly CspOptions customCspWithNonce = new CspOptions()
            .AllowSelf()
            .AllowFrameSources("https://httpbin.org", "https://jsonplaceholder.typicode.com")
            .AllowHttpsFrames()
            .AllowDataUrls()
            .WithScriptNonce("custom-nonce-456")
            .WithCustomDirective("img-src", "'self'", "data:", "https:")
            .WithCustomDirective("connect-src", "'self'", "https:");

        private readonly CspOptions strictCspOptions = new CspOptions()
            .ForProduction()
            .AllowFrameSources("https://httpbin.org")
            .UseStrictDynamic()
            .WithScriptNonce("strict-nonce-789");

        private readonly CspOptions reportOnlyCsp = new CspOptions()
            .AllowSelf()
            .AllowHttpsFrames()
            .AsReportOnly("https://csp-report.example.com/violations");

        // Event logging
        private List<LogEntry> eventLog = new();
        private List<CspValidationSummary> cspValidationResults = new();

        private class LogEntry
        {
            public DateTime Timestamp { get; set; } = DateTime.Now;
            public string Type { get; set; } = "";
            public string Message { get; set; } = "";
            public string Details { get; set; } = "";
        }

        private class CspValidationSummary
        {
            public string ConfigName { get; set; } = "";
            public bool IsValid { get; set; }
            public List<string> Warnings { get; set; } = new();
            public List<string> Suggestions { get; set; } = new();
        }

        // Event handlers
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
            AddLogEntry("SECURITY", $"Security violation: {violation.ValidationError}",
                $"Origin: {violation.Origin}, Data: {TruncateString(violation.Data, 50)}");
            StateHasChanged();
        }

        private async Task HandleRestrictedMessage(IframeMessage message)
        {
            AddLogEntry("RESTRICTED", $"Message allowed through restricted iframe from {message.Origin}",
                $"Data: {TruncateString(message.Data, 100)}");
        }

        private async Task HandleRestrictedSecurityViolation(IframeMessage violation)
        {
            AddLogEntry("SECURITY", $"Restricted iframe violation: {violation.ValidationError}",
                $"Origin: {violation.Origin}");
        }

        private async Task HandleInitializationError(Exception ex)
        {
            AddLogEntry("ERROR", "Iframe initialization failed", ex.Message);
        }

        // CSP Event Handlers
        private async Task HandleCspHeaderGenerated(CspHeader cspHeader)
        {
            cspHeadersGenerated++;
            lastGeneratedCspHeader = cspHeader.HeaderValue;
            AddLogEntry("CSP", $"CSP header generated: {cspHeader.HeaderName}",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
            StateHasChanged();
        }

        private async Task HandleStrictCspGenerated(CspHeader cspHeader)
        {
            AddLogEntry("CSP", $"Strict CSP header generated",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
        }

        private async Task HandleDevelopmentCspGenerated(CspHeader cspHeader)
        {
            AddLogEntry("CSP", $"Development CSP header generated",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
        }

        private async Task HandleProductionCspGenerated(CspHeader cspHeader)
        {
            AddLogEntry("CSP", $"Production CSP header generated",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
        }

        private async Task HandleCustomCspGenerated(CspHeader cspHeader)
        {
            AddLogEntry("CSP", $"Custom CSP header generated",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
        }

        private async Task HandleReportOnlyCspGenerated(CspHeader cspHeader)
        {
            AddLogEntry("CSP", $"Report-only CSP header generated",
                $"Value: {TruncateString(cspHeader.HeaderValue, 150)}");
        }

        // Control handlers
        private async Task OnUrlChange(ChangeEventArgs e)
        {
            currentUrl = e.Value?.ToString() ?? "";
            isLoaded = false;
            AddLogEntry("URL_CHANGE", $"URL changed to: {currentUrl}");
            StateHasChanged();
        }

        private async Task OnSecurityLevelChange(ChangeEventArgs e)
        {
            var level = e.Value?.ToString() ?? "moderate";
            currentSecurityOptions = level switch
            {
                "strict" => new MessageSecurityOptions
                {
                    EnableStrictValidation = true,
                    MaxMessageSize = 16 * 1024,
                    LogSecurityViolations = true,
                    MaxJsonDepth = 5,
                    MaxObjectProperties = 20,
                    MaxArrayElements = 50
                },
                "relaxed" => new MessageSecurityOptions
                {
                    EnableStrictValidation = false,
                    MaxMessageSize = 128 * 1024,
                    LogSecurityViolations = true,
                    MaxJsonDepth = 20,
                    MaxObjectProperties = 500,
                    MaxArrayElements = 1000
                },
                _ => new MessageSecurityOptions
                {
                    EnableStrictValidation = true,
                    MaxMessageSize = 64 * 1024,
                    LogSecurityViolations = true
                }
            };

            AddLogEntry("SECURITY_CHANGE", $"Security level changed to: {level}");
            StateHasChanged();
        }

        private async Task OnCspModeChange(ChangeEventArgs e)
        {
            currentCspMode = e.Value?.ToString() ?? "none";

            currentCspOptions = currentCspMode switch
            {
                "development" => new CspOptions()
                    .ForDevelopment()
                    .AllowFrameSources(ExtractOriginFromUrl(currentUrl)),
                "production" => new CspOptions()
                    .ForProduction()
                    .AllowFrameSources(ExtractOriginFromUrl(currentUrl))
                    .WithScriptNonce($"nonce-{DateTime.Now.Ticks}"),
                "custom" => new CspOptions()
                    .AllowSelf()
                    .AllowFrameSources(ExtractOriginFromUrl(currentUrl))
                    .AllowHttpsFrames()
                    .AllowDataUrls()
                    .WithCustomDirective("img-src", "'self'", "data:", "https:")
                    .WithCustomDirective("connect-src", "'self'", "https:"),
                _ => null
            };

            AddLogEntry("CSP_CHANGE", $"CSP mode changed to: {currentCspMode}");
            StateHasChanged();
        }

        private async Task SendTestMessage()
        {
            var message = """{"type": "test", "data": "Hello from BlazorFrame demo!", "timestamp": """ +
                          DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + "}";

            await SendMessageToIframes(message);
            AddLogEntry("SEND", "Sent test message");
        }

        private async Task SendLargeMessage()
        {
            var largeData = new string('A', 100 * 1024);
            var message = $@"{{""type"": ""large"", ""data"": ""{largeData}""}}";
            await SendMessageToIframes(message);
            AddLogEntry("SEND", "Sent large message (100KB)");
        }

        private async Task SendMaliciousMessage()
        {
            var message = """{"type": "malicious", "data": "<script>alert('XSS')</script>", "eval": "eval('console.log(\"test\")')"}""";
            await SendMessageToIframes(message);
            AddLogEntry("SEND", "Sent potentially malicious message");
        }

        private async Task SendCustomMessage()
        {
            if (!string.IsNullOrWhiteSpace(customMessage))
            {
                await SendMessageToIframes(customMessage);
                AddLogEntry("SEND", "Sent custom message", customMessage);
            }
        }

        private async Task ValidateAllCspConfigurations()
        {
            var cspBuilder = new BlazorFrame.Services.CspBuilderService();

            var configurations = new Dictionary<string, CspOptions>
            {
                { "Development", developmentCsp },
                { "Production", productionCsp },
                { "Custom with Nonce", customCspWithNonce },
                { "Strict", strictCspOptions },
                { "Report Only", reportOnlyCsp }
            };

            cspValidationResults.Clear();

            foreach (var config in configurations)
            {
                var validation = cspBuilder.ValidateCspOptions(config.Value);
                cspValidationResults.Add(new CspValidationSummary
                {
                    ConfigName = config.Key,
                    IsValid = validation.IsValid,
                    Warnings = validation.Warnings,
                    Suggestions = validation.Suggestions
                });

                AddLogEntry("CSP_VALIDATION", $"Validated {config.Key} CSP",
                    $"Valid: {validation.IsValid}, Warnings: {validation.Warnings.Count}, Suggestions: {validation.Suggestions.Count}");
            }

            StateHasChanged();
        }

        private async Task TestCspMetaTagGeneration()
        {
            if (currentCspOptions != null)
            {
                var cspBuilder = new BlazorFrame.Services.CspBuilderService();
                var metaTag = cspBuilder.BuildCspMetaTag(currentCspOptions, new[] { currentUrl });

                AddLogEntry("CSP_META", "Generated CSP meta tag", metaTag);
            }
            else
            {
                AddLogEntry("CSP_META", "No CSP configuration active", "Please select a CSP mode first");
            }
        }

        private async Task TestCspJavaScriptGeneration()
        {
            if (currentCspOptions != null)
            {
                var cspBuilder = new BlazorFrame.Services.CspBuilderService();
                var jsCode = cspBuilder.BuildCspJavaScript(currentCspOptions, new[] { currentUrl });

                AddLogEntry("CSP_JS", "Generated CSP JavaScript", TruncateString(jsCode, 200));
            }
            else
            {
                AddLogEntry("CSP_JS", "No CSP configuration active", "Please select a CSP mode first");
            }
        }

        private async Task SendMessageToIframes(string message)
        {
            // For now, just log the message - will implement actual message sending once BlazorFrame API is confirmed
            Logger.LogInformation("Would send message to iframes: {Message}", message);
            await Task.CompletedTask;
        }

        // Utility methods
        private void AddLogEntry(string type, string message, string details = "")
        {
            eventLog.Add(new LogEntry { Type = type, Message = message, Details = details });
            if (eventLog.Count > 100) // Keep log manageable
            {
                eventLog.RemoveAt(0);
            }
        }

        private void ClearLog()
        {
            eventLog.Clear();
            messageCount = 0;
            securityViolations = 0;
            cspHeadersGenerated = 0;
            cspValidationResults.Clear();
            StateHasChanged();
        }

        private string GetLogEntryClass(string type) => type.ToLower() switch
        {
            "load" or "message" or "restricted" => "success",
            "security" => "security",
            "csp" or "csp_validation" or "csp_meta" or "csp_js" => "csp",
            "error" => "error",
            "send" or "url_change" or "security_change" or "csp_change" => "info",
            _ => "info"
        };

        private static string TruncateString(string input, int maxLength)
        {
            if (string.IsNullOrEmpty(input) || input.Length <= maxLength)
                return input;
            return input[..maxLength] + "...";
        }

        private static string ExtractOriginFromUrl(string url)
        {
            try
            {
                if (url.StartsWith("data:")) return "data:";
                if (url.StartsWith("blob:")) return "blob:";

                var uri = new Uri(url);
                return uri.GetLeftPart(UriPartial.Authority);
            }
            catch
            {
                return "'self'";
            }
        }
    }
}