using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using io.fusionauth;
using io.fusionauth.domain.api.identityProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace FusionAuthTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OAuth2Controller(FusionAuthSyncClient client) : ControllerBase
    {
        private readonly FusionAuthSyncClient _client = client;
        private readonly Guid _applicationId = new("ac3c2bbc-45f6-4daf-bd55-86529b296faa");

        [HttpGet("/oauth2/callback")]
        public async Task<IActionResult> OAuth2Callback([FromQuery] string code)
        {
            var configurations =
                _client.RetrieveOauthConfiguration(_applicationId);

            var clientId = configurations.successResponse.oauthConfiguration.clientId;
            var clientSecret = configurations.successResponse.oauthConfiguration.clientSecret;
            var redirectUri = "https://localhost:7205/oauth2/callback";

            var response = _client.ExchangeOAuthCodeForAccessToken(code, clientId, clientSecret, redirectUri);

            var resultDict = new Dictionary<string, string>
            {
                {"access_token", response.successResponse.access_token},
                {"refresh_token", response.successResponse.refresh_token},
                {"expires_in", response.successResponse.expires_in.ToString()},
                {"token_type", response.successResponse.token_type.ToString()},
                {"scope", response.successResponse.scope},
                {"id_token", response.successResponse.id_token},
                {"refresh_token_id", response.successResponse.refresh_token_id.ToString()}
            };

            return Ok(resultDict);
        }
    }
}