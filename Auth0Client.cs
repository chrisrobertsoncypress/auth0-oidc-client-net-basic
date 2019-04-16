using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using RestSharp;

namespace SampleWeb
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
            
        public Auth0Client(string clientId, string domain)
        {
            _clientId = clientId;
            _domain = domain;
            _windowFactory = () => new Window {
                Name = "LoginWindow",
                Title = "Your title here",
                Width = 768,
                Height = 800
            };
        }

        public async Task<LoginResult> LoginAsync(string loginHint = null)
        {
            var window = _windowFactory.Invoke();
            try
            {
                var grid = new Grid();

                window.Content = grid;
                var browser = new WebBrowser();

                var signal = new SemaphoreSlim(0, 1);
                var result = new LoginResult { IsSuccessful = false, Tokens = null };
                window.Closed += (o, e) =>
                {
                    signal.Release();
                };
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
                            signal.Release();
                        }
                    }
                };

                grid.Children.Add(browser);
                window.Show();

                _codeVerifier = GetRandomString();
                browser.Navigate(GetLoginUrl(_codeVerifier, loginHint));

                await signal.WaitAsync();

                return result;
            }
            finally
            {
                window.Close();
            }
        }

        public void Logout()
        {
            var browser = new WebBrowser();
            browser.Navigate(GetLogoutUrl());
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

        private string Base64URLEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').Replace("=", "");
        }

    }

    public class LoginResult
    {
        public bool IsSuccessful;
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
