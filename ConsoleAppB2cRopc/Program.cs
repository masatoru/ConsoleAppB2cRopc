using Microsoft.Identity.Client;
using System;
using System.Linq;
using System.Security;
using System.Threading.Tasks;

namespace ConsoleAppB2cRopc
{
    class Program
    {
        // Azure AD B2C Coordinates
        private static string Tenant = "{{Your Tenant Name}}.onmicrosoft.com";
        private static string AzureADB2CHostname = "{{Your Tenant Name}}.b2clogin.com";
        private static string ClientID = "{{Your Client ID}}";
        private static string PolicyRopc = "{{Your ROPC Flow}}"; // ex)B2C_1_orpc_signin
        private static string AuthorityBase = $"https://{AzureADB2CHostname}/tfp/{Tenant}/";
        private static string Authority = $"{AuthorityBase}{PolicyRopc}";
        private static string[] Scopes { get; } = { $"https://{Tenant}/{ClientID}/api", "openid", "offline_access" };

        private static IPublicClientApplication App { get; set; }

        static async Task Main(string[] args)
        {
            var username = Sharprompt.Prompt.Input<string>("Input username.");
            var password = Sharprompt.Prompt.Password("Input password.");

            var passwordText = new SecureString();
            foreach (var c in password)
            {
                passwordText.AppendChar(c);
            }

            App = PublicClientApplicationBuilder.Create(ClientID)
                .WithB2CAuthority(Authority)
                .Build();

            AuthenticationResult result = null;
            var accounts = await App.GetAccountsAsync();
            var account = accounts.FirstOrDefault();

            try
            {
                result = await App.AcquireTokenSilent(Scopes, account)
                    .ExecuteAsync();
            }
            catch (MsalUiRequiredException)
            {
                try
                {
                    result = await App.AcquireTokenByUsernamePassword(Scopes, username, passwordText)
                        .ExecuteAsync();
                }
                catch (MsalUiRequiredException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ex.Message);
                    Console.ResetColor();
                }
                // AADB2C90225: The username or password provided in the request are invalid.
                catch (MsalServiceException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ex.Message);
                    Console.ResetColor();
                }
            }

            // Cache empty or no token for account in the cache, attempt by username/password
            if (result != null)
            {
                Console.WriteLine($"IdToken: {result.IdToken}");
                Console.WriteLine($"AccessToken: {result.AccessToken}");
            }
        }
    }
}
