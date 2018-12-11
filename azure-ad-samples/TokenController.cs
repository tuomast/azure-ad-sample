using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;


// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace azureadsamples
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        //
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Tenant is the name of the tenant in which this application is registered.
        // The Authority is the sign-in URL of the tenant.
        // The Audience is the value the service expects to see in tokens that are addressed to it.
        //
        private static string aadInstance = "https://login.microsoftonline.com/common";
        
        private static string clientId = "1f1b16ce-1443-43a6-8837-49ef790cc61a";
    
        private static string _issuer = string.Empty;
        private static ICollection<SecurityKey> _signingKeys = null;
        private static DateTime _stsMetadataRetrievalTime = DateTime.MinValue;
        private static string scopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";


        public async Task<JwtSecurityToken> Validate(string token)
        {
            string stsDiscoveryEndpoint = "https://login.microsoftonline.com/common/.well-known/openid-configuration";

            string issuer;
            ICollection<SecurityKey> signingKeys;

            try {
                // The issuer and signingKeys are cached for 24 hours. They are updated if any of the conditions in the if condition is true.
                if (DateTime.UtcNow.Subtract(_stsMetadataRetrievalTime).TotalHours > 24
                    || string.IsNullOrEmpty(_issuer)
                    || _signingKeys == null) {
                    // Get tenant information that's used to validate incoming jwt tokens
                    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
                    var config = await configManager.GetConfigurationAsync();
                    _issuer = config.Issuer;
                    _signingKeys = config.SigningKeys;

                    _stsMetadataRetrievalTime = DateTime.UtcNow;
                }

                signingKeys = _signingKeys;
            } catch (Exception)
            {
                return null;
            }

            TokenValidationParameters validationParameters = new TokenValidationParameters {
                // We accept both the App Id URI and the AppId of this service application
                ValidAudiences = new[] { clientId },

                ValidateIssuer = false,
                IssuerSigningKeys = signingKeys
            };

            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            SecurityToken jwt;

            var result = tokendHandler.ValidateToken(token, validationParameters, out jwt);

            return jwt as JwtSecurityToken;
        }


        [HttpPost]
        public async Task<IActionResult> Index([FromHeader] string authorization )
        {
            AuthenticationHeaderValue auth = AuthenticationHeaderValue.Parse(authorization);

            var response = await Validate(auth.Parameter);
            
            return Content(string.Join("\n", response.Claims.Select( c => c.ToString() )));
        }
    }
}
