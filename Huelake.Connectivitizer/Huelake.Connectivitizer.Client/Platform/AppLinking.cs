using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Platform;

/// <summary>
/// Links an application to somebody's account without a login inside the application: the
/// person approves in the web app, and the application receives an API key of its own.
/// </summary>
/// <example>
/// <code>
/// LinkTokenResponse linked = await AppLinking.LinkAsync(api, "Lamp app", link =>
/// {
///     Console.WriteLine($"Open {link.VerificationUrlComplete} and check the code {link.UserCode}");
///     return Task.CompletedTask;
/// });
/// // Store linked.ApiKey where only this application can read it, and use it as ApiKey from then on.
/// </code>
/// </example>
public static class AppLinking
{
    /// <summary>
    /// Starts a link, hands <paramref name="prompt"/> the address to open and the code to compare,
    /// and waits until the person has decided.
    /// </summary>
    /// <param name="client">The name the application appears under in the workspace.</param>
    /// <param name="prompt">Shows the person where to go: opens a browser, prints the address, draws a QR code.</param>
    /// <returns>The API key and the workspace it belongs to. The key is returned this once and never again.</returns>
    /// <exception cref="PlatformException"><see cref="ErrorCodes.LinkDenied"/> when the person refused, <see cref="ErrorCodes.LinkExpired"/> when nobody decided in time.</exception>
    public static async Task<LinkTokenResponse> LinkAsync(Uri apiUrl, string client, Func<LinkStartResponse, Task> prompt, string? platform = null, HttpClient? http = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(client);
        ArgumentNullException.ThrowIfNull(prompt);

        var api = new PlatformApi(apiUrl, http);
        LinkStartResponse link = await api.StartLinkAsync(client, platform, cancellationToken).ConfigureAwait(false);
        await prompt(link).ConfigureAwait(false);

        DateTime deadline = DateTime.UtcNow.AddSeconds(link.ExpiresIn);
        TimeSpan interval = TimeSpan.FromSeconds(Math.Clamp(link.Interval, 1, 30));
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
            LinkTokenResponse answer = await api.PollLinkAsync(link.DeviceCode, cancellationToken).ConfigureAwait(false);
            if (answer is { Status: LinkStatuses.Approved, ApiKey: not null })
            {
                return answer;
            }
        }
        throw new PlatformException(ErrorCodes.LinkExpired, "Nobody approved the link in time.");
    }
}
