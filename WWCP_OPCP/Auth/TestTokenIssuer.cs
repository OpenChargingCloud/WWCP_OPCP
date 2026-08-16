/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of WWCP OPCP <https://github.com/OpenChargingCloud/WWCP_OPCP>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Issues and verifies HMAC-signed access tokens for a self-contained OPCP ecosystem.
    ///
    /// A real ecosystem hands this job to an identity provider signing RS256 tokens against a
    /// published key set. That is a dependency an in-process test cannot have and should not
    /// want, so this issues the same claims over HS256 instead: the claim vocabulary the services
    /// authorize against is identical, only the signature is symmetric.
    /// </summary>
    /// <remarks>
    /// HS256 means the party checking a token could also have minted it. That is exactly why this
    /// belongs to a test ecosystem and to nothing else - point production at an
    /// <see cref="IAccessTokenValidator"/> that verifies the real issuer's asymmetric signature.
    /// </remarks>
    public class TestTokenIssuer : IAccessTokenValidator
    {

        #region Data

        private readonly Byte[] signingKey;

        /// <summary>
        /// How long an issued token is valid by default. The specification's own tokens last 24 hours.
        /// </summary>
        public static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(24);

        #endregion

        #region Properties

        /// <summary>
        /// The deployment this issuer mints tokens for. Also the namespace of the OPCP claims
        /// and the audience of the tokens.
        /// </summary>
        public URL     Audience    { get; }

        /// <summary>
        /// The issuer named in the tokens.
        /// </summary>
        public String  Issuer      { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new test token issuer.
        /// </summary>
        /// <param name="Audience">The deployment to mint tokens for.</param>
        /// <param name="Issuer">An optional issuer, otherwise derived from the audience.</param>
        /// <param name="SigningKey">An optional signing key, otherwise a random one.</param>
        public TestTokenIssuer(URL      Audience,
                               String?  Issuer       = null,
                               Byte[]?  SigningKey   = null)
        {

            this.Audience    = Audience;
            this.Issuer      = Issuer ?? $"{Audience}/";
            this.signingKey  = SigningKey ?? RandomNumberGenerator.GetBytes(32);

        }

        #endregion


        #region IssueToken(Roles = null, WMIs = null, ProviderIds = null, ...)

        /// <summary>
        /// Issue an access token.
        /// </summary>
        /// <param name="Roles">The roles the holder acts in.</param>
        /// <param name="WMIs">The World Manufacturer Identifiers the holder may act for.</param>
        /// <param name="ProviderIds">The e-mobility provider identifications the holder may act for.</param>
        /// <param name="ClientName">An optional name for the client.</param>
        /// <param name="Scopes">Optional scopes.</param>
        /// <param name="Lifetime">An optional lifetime, otherwise 24 hours.</param>
        /// <param name="IssuedAt">An optional moment of issuance, otherwise now.</param>
        public AccessTokenResponse IssueToken(IEnumerable<OPCPRole>?     Roles         = null,
                                              IEnumerable<WMI>?          WMIs          = null,
                                              IEnumerable<Provider_Id>?  ProviderIds   = null,
                                              String?                    ClientName    = null,
                                              IEnumerable<String>?       Scopes        = null,
                                              TimeSpan?                  Lifetime      = null,
                                              DateTimeOffset?            IssuedAt      = null)
        {

            var issuedAt   = IssuedAt ?? DateTimeOffset.UtcNow;
            var lifetime   = Lifetime ?? DefaultLifetime;
            var scopes     = Scopes?.ToArray() ?? [];

            var claims     = new JObject();

            // The OPCP claims are namespaced by the deployment's own URL, exactly as the
            // specification's example token spells them.
            if (Roles is not null && Roles.Any())
                claims.Add($"{Audience}/role",         new JArray(Roles.      Select(role       => role.      ToString())));

            if (WMIs is not null && WMIs.Any())
                claims.Add($"{Audience}/pcid",         new JArray(WMIs.       Select(wmi        => wmi.       ToString())));

            if (ProviderIds is not null && ProviderIds.Any())
                claims.Add($"{Audience}/emaid",        new JArray(ProviderIds.Select(providerId => providerId.ToString())));

            if (ClientName.IsNotNullOrEmpty())
                claims.Add($"{Audience}/client_name",  new JArray(ClientName));

            claims.Add("iss",    Issuer);
            claims.Add("sub",    $"{ClientName ?? "client"}@clients");
            claims.Add("aud",    Audience.ToString());
            claims.Add("iat",    issuedAt.ToUnixTimeSeconds());
            claims.Add("exp",    (issuedAt + lifetime).ToUnixTimeSeconds());
            claims.Add("gty",    AccessTokenRequest.ClientCredentials.Replace('_', '-'));

            if (scopes.Length != 0)
            {
                claims.Add("scope",        String.Join(" ", scopes));
                claims.Add("permissions",  new JArray(scopes));
            }

            return new AccessTokenResponse(
                       Sign(claims),
                       String.Join(" ", scopes),
                       lifetime,
                       "Bearer",
                       issuedAt
                   );

        }

        #endregion

        #region TryValidate(Token, out TokenInfo, out ErrorResponse)

        /// <summary>
        /// Verify a token this issuer minted.
        /// </summary>
        /// <param name="Token">A JSON Web Token, without the "Bearer " prefix.</param>
        /// <param name="TokenInfo">The verified claims.</param>
        /// <param name="ErrorResponse">Why the token was not accepted.</param>
        public Boolean TryValidate(String                                   Token,
                                   [NotNullWhen(true)]  out OPCPTokenInfo?  TokenInfo,
                                   [NotNullWhen(false)] out String?         ErrorResponse)
        {

            TokenInfo      = null;
            ErrorResponse  = null;

            var parts = (Token ?? "").Trim().Split('.');

            if (parts.Length != 3)
            {
                ErrorResponse = "A JSON Web Token must have three dot-separated parts!";
                return false;
            }

            #region Verify the signature before reading anything

            if (!Base64URL.TryDecodeUTF8(parts[0], out var headerText))
            {
                ErrorResponse = "The header of the given token is not valid base64url!";
                return false;
            }

            String? algorithm;

            try
            {
                algorithm = JObject.Parse(headerText).Value<String>("alg");
            }
            catch
            {
                ErrorResponse = "The header of the given token is not valid JSON!";
                return false;
            }

            if (algorithm != "HS256")
            {
                // Refusing anything else by name is the point: a token asking to be verified
                // with "none", or with an algorithm this issuer does not use, is not a token
                // this issuer signed.
                ErrorResponse = $"This issuer only accepts HS256 tokens, not '{algorithm}'!";
                return false;
            }

            var expected = Base64URL.Encode(HMACSHA256.HashData(signingKey,
                                                                Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}")));

            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected),
                                                         Encoding.UTF8.GetBytes(parts[2])))
            {
                ErrorResponse = "The signature of the given token is invalid!";
                return false;
            }

            #endregion

            if (!OPCPTokenInfo.TryParse(Token!, out var tokenInfo, out ErrorResponse))
                return false;

            if (tokenInfo.IsExpiredAt(DateTimeOffset.UtcNow))
            {
                ErrorResponse = "The given token has expired!";
                return false;
            }

            TokenInfo = tokenInfo;
            return true;

        }

        #endregion

        #region TryValidate(Authentication, out TokenInfo, out ErrorResponse)

        /// <summary>
        /// Verify the bearer token of an HTTP request.
        /// </summary>
        /// <param name="Authentication">The authentication of an HTTP request.</param>
        /// <param name="TokenInfo">The verified claims.</param>
        /// <param name="ErrorResponse">Why the token was not accepted.</param>
        public Boolean TryValidate(IHTTPAuthentication?                     Authentication,
                                   [NotNullWhen(true)]  out OPCPTokenInfo?  TokenInfo,
                                   [NotNullWhen(false)] out String?         ErrorResponse)
        {

            if (Authentication is not HTTPBearerAuthentication bearer)
            {
                TokenInfo      = null;
                ErrorResponse  = "The request carries no bearer token!";
                return false;
            }

            return TryValidate(bearer.Token, out TokenInfo, out ErrorResponse);

        }

        #endregion


        #region (private) Sign(Claims)

        /// <summary>
        /// Assemble and sign a JSON Web Token.
        /// </summary>
        private String Sign(JObject Claims)
        {

            var header      = Base64URL.Encode(new JObject(
                                                   new JProperty("alg",  "HS256"),
                                                   new JProperty("typ",  "JWT")
                                               ).ToString(Formatting.None));

            var payload     = Base64URL.Encode(Claims.ToString(Formatting.None));

            var signature   = Base64URL.Encode(HMACSHA256.HashData(signingKey,
                                                                   Encoding.UTF8.GetBytes($"{header}.{payload}")));

            return $"{header}.{payload}.{signature}";

        }

        #endregion

    }

}
