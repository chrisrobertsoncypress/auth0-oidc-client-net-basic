using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using RestSharp;

namespace YourNamespace
{
   /* Code copied from https://github.com/auth0/auth0-oidc-client-net
   *  That Nuget package needed about fifty .NET Core dependencies,
   *  which would have badly affected startup time, 
   *  so just copied necessary methods here.
   */
    public class Auth0Client
    {

        private readonly Func<Window> _windowFactory;
        private readonly string _clientId;
        private readonly string _domain;
        private string _codeVerifier;

        public Auth0Client(string domain, string clientId)
        {
            _domain = domain;
            _clientId = clientId;
            _windowFactory = () => new Window
            {
                Name = "LoginWindow",
                Title = "Your Title Here",
                Width = 768,
                Height = 800
            };
        }

        public async Task<LoginResult> LoginAsync(string loginHint = null)
        {
            if (!IsNetworkAvailable())
            {
                return new LoginResult { IsSuccessful = false, Tokens = null, ErrorMessage = "You must have an internet connection." };
            }
            var result = new LoginResult { IsSuccessful = false, Tokens = null };
            var window = _windowFactory.Invoke();
            var semaphore = new SemaphoreSlim(0, 1);
            var closedByUser = true;
            window.Closed += (object sender, EventArgs e) =>
            {
                if (closedByUser && !result.IsSuccessful)
                {
                    result.ErrorMessage = "You must login to continue.";
                }
                EnsureSemaphoreReleased(semaphore);
            };
            try
            {
                var grid = new Grid();
                window.Content = grid;
                var browser = new WebBrowser();
                browser.LoadCompleted += (sender, args) =>
                {
                    var query = HttpUtility.ParseQueryString(args.Uri.Query);
                    var code = query["code"];
                    if (!String.IsNullOrEmpty(code))
                    {
                        IRestResponse response = MakeTokenRequest(code);
                        if (response.IsSuccessful)
                        {
                            var tokens = SimpleJson.DeserializeObject<Tokens>(response.Content);
                            result = new LoginResult { IsSuccessful = true, Tokens = tokens };
                        }
                        semaphore.Release();
                    }
                };

                grid.Children.Add(browser);
                window.Show();
                _codeVerifier = GetRandomString();
                browser.Navigate(GetLoginUrl(_codeVerifier, loginHint));

                // Wait here until browser loads and on the 2nd loading time (with the code) semaphone.Release() will be called
                await semaphore.WaitAsync();
                return result;
            }
            catch (Exception ex)
            {
                return new LoginResult { IsSuccessful = false, Tokens = null, ErrorMessage = ex.Message };
            }
            finally
            {
                closedByUser = false;
                window.Close();
                EnsureSemaphoreReleased(semaphore);
            }
        }

        public async Task<bool> LogoutAsync()
        {
            var result = false;
            var browser = new WebBrowser();
            var semaphore = new SemaphoreSlim(0, 1);
            try
            {
                browser.Navigated += (sender, args) =>
                {
                    result = true;
                    semaphore.Release();
                };
                browser.Navigate(GetLogoutUrl());
                await semaphore.WaitAsync();
            }
            finally
            {
                EnsureSemaphoreReleased(semaphore);
            }
            return result;
        }

        public void Logout()
        {
            var browser = new WebBrowser();
            browser.Navigate(GetLogoutUrl());
        }

        public bool RevokeRefreshToken(string refreshToken)
        {
            var request = new RestRequest(Method.POST);
            request.Resource = "oauth/revoke";
            request.AddParameter("token", refreshToken);
            request.AddParameter("client_id", _clientId);
            var client = new RestClient(String.Format("https://{0}", _domain));
            var response = client.Execute(request);
            return response.IsSuccessful;
        }

        private bool IsNetworkAvailable()
        {
            var request = new RestRequest(Method.HEAD);
            var client = new RestClient("https://www.google.com");
            var response = client.Execute(request);
            return response.StatusCode != 0;
        }

        private IRestResponse MakeTokenRequest(string code)
        {
            var request = new RestRequest(Method.POST);
            request.Resource = "oauth/token";
            request.AddParameter("grant_type", "authorization_code");
            request.AddParameter("code_verifier", _codeVerifier);
            request.AddParameter("code", code);
            request.AddParameter("client_id", _clientId);
            request.AddParameter("redirect_uri", String.Format("https://{0}/mobile", _domain));
            var client = new RestClient(String.Format("https://{0}", _domain));
            var response = client.Execute(request);
            return response;
        }

        private string GetLoginUrl(string codeVerifier, string loginHint = null)
        {
            var codeChallenge = Base64URLEncode(HashString(codeVerifier));
            var loginUrl = String.Format(
                "https://{0}/authorize" +
                "?response_type=code&code_challenge={1}" +
                "&code_challenge_method=S256&client_id={2}" +
                "&redirect_uri=https://{3}/mobile&scope=openid offline_access",
                _domain,
                codeChallenge,
                _clientId,
                _domain);
            if (!String.IsNullOrEmpty(loginHint))
            {
                loginUrl += String.Format("&login_hint={0}", loginHint);
            }
            return loginUrl;
        }

        private string GetLogoutUrl()
        {
            var logoutUrl = String.Format(
                  "https://{0}/v2/logout" +
                  "?client_id={1}" +
                  "&returnTo=https://{2}/mobile",
                  _domain,
                  _clientId,
                  _domain);
            return logoutUrl;
        }
        private static byte[] HashString(string input)
        {
            using (var hasher = SHA256.Create())
            {
                return hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        private static string GetRandomString()
        {
            var rand = new RNGCryptoServiceProvider();
            var randomBytes = new byte[64];
            rand.GetBytes(randomBytes);
            return ByteArrayToString(randomBytes);
        }
        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            return hex.ToString();
        }

        private static void EnsureSemaphoreReleased(SemaphoreSlim semaphore)
        {
            if (semaphore.CurrentCount == 0)
            {
                semaphore.Release();
            }
        }

        private string Base64URLEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').Replace("=", "");
        }

    }

    public class LoginResult
    {
        public bool IsSuccessful;
        public string ErrorMessage;
        public Tokens Tokens;
    }

    public class Tokens
    {
        public string access_token;
        public string refresh_token;
        public string id_token;
        public int expires_in;
    }
}
