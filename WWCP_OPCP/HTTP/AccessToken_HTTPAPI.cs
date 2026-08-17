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

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The OAuth2 token endpoint of a self-contained OPCP ecosystem.
    ///
    /// A real deployment hands this to an identity provider - the specification's own tokens come
    /// from Auth0 - and this is not a replacement for one. It exists so that an ecosystem can be
    /// run end to end in one process: a client with a client identification and secret gets a
    /// token, and that token opens the six services, without anything outside being involved.
    /// </summary>
    /// <remarks>
    /// The tokens are HMAC-signed by a <see cref="TestTokenIssuer"/>, which means the party
    /// checking them could equally have minted them. That is fine for a development or test
    /// ecosystem and wrong for anything else.
    /// </remarks>
    public class AccessToken_HTTPAPI : AOPCPHTTPAPI
    {

        #region (class) RegisteredClient

        /// <summary>
        /// A client this endpoint will issue tokens to.
        /// </summary>
        /// <param name="ClientSecret">The secret the client authenticates with.</param>
        /// <param name="Roles">The roles it acts in.</param>
        /// <param name="WMIs">The vehicle manufacturers it may act for.</param>
        /// <param name="ProviderIds">The e-mobility providers it may act for.</param>
        /// <param name="ClientName">The name the ecosystem knows it by.</param>
        /// <param name="Scopes">The scopes its tokens open.</param>
        private sealed record RegisteredClient(String                    ClientSecret,
                                               IEnumerable<OPCPRole>     Roles,
                                               IEnumerable<WMI>          WMIs,
                                               IEnumerable<Provider_Id>  ProviderIds,
                                               String                    ClientName,
                                               IEnumerable<String>       Scopes);

        #endregion

        #region Data

        /// <summary>
        /// Where the token endpoint is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/oauth");

        private readonly ConcurrentDictionary<String, RegisteredClient> clients = new (StringComparer.Ordinal);

        #endregion

        #region Properties

        /// <summary>
        /// What signs the tokens this endpoint issues - and what the services verify them with.
        /// </summary>
        public TestTokenIssuer  TokenIssuer    { get; }

        /// <summary>
        /// The audience of the tokens this endpoint issues.
        /// </summary>
        public URL              Audience
            => TokenIssuer.Audience;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OAuth2 token endpoint.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="TokenIssuer">What signs the issued tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public AccessToken_HTTPAPI(HTTPServer       HTTPServer,
                                   TestTokenIssuer  TokenIssuer,
                                   HTTPPath?        RootPath      = null)

            : base(HTTPServer,
                   null,   // obtaining a token is what this endpoint is for
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Access Token Endpoint"))

        {

            this.TokenIssuer = TokenIssuer;

            RegisterURLTemplates();

        }

        #endregion


        #region RegisterClient(ClientId, ClientSecret, ...)

        /// <summary>
        /// Admit a client, and say what its tokens will permit.
        /// </summary>
        /// <param name="ClientId">The identification the client authenticates with.</param>
        /// <param name="ClientSecret">The secret the client authenticates with.</param>
        /// <param name="Roles">The roles it acts in.</param>
        /// <param name="WMIs">The vehicle manufacturers it may act for.</param>
        /// <param name="ProviderIds">The e-mobility providers it may act for.</param>
        /// <param name="ClientName">An optional name for the client.</param>
        /// <param name="Scopes">Optional scopes.</param>
        public void RegisterClient(String                     ClientId,
                                   String                     ClientSecret,
                                   IEnumerable<OPCPRole>?     Roles         = null,
                                   IEnumerable<WMI>?          WMIs          = null,
                                   IEnumerable<Provider_Id>?  ProviderIds   = null,
                                   String?                    ClientName    = null,
                                   IEnumerable<String>?       Scopes        = null)
        {

            if (ClientId.IsNullOrEmpty())
                throw new ArgumentException("The given client identification must not be null or empty!", nameof(ClientId));

            if (ClientSecret.IsNullOrEmpty())
                throw new ArgumentException("The given client secret must not be null or empty!", nameof(ClientSecret));

            clients[ClientId] = new RegisteredClient(
                                    ClientSecret,
                                    Roles?.      ToArray() ?? [],
                                    WMIs?.       ToArray() ?? [],
                                    ProviderIds?.ToArray() ?? [],
                                    ClientName ?? ClientId,
                                    Scopes?.     ToArray() ?? []
                                );

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region POST    ~/oauth/token   issue-token

            AddHandler(
                HTTPMethod.POST,
                Route("token"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: request => {

                    if (!TryParseJSONBody(request, out var json, out var response))
                        return Task.FromResult(response);

                    if (!AccessTokenRequest.TryParse(json, out var tokenRequest, out var errorResponse))
                        return Task.FromResult(
                                   OAuthError(request,
                                              HTTPStatusCode.BadRequest,
                                              "invalid_request",
                                              errorResponse)
                               );

                    if (tokenRequest.GrantType != AccessTokenRequest.ClientCredentials)
                        return Task.FromResult(
                                   OAuthError(request,
                                              HTTPStatusCode.BadRequest,
                                              "unsupported_grant_type",
                                              $"This endpoint only supports '{AccessTokenRequest.ClientCredentials}'.")
                               );

                    #region Authenticate the client

                    // One refusal for an unknown client and for a wrong secret alike: telling
                    // the two apart would turn this endpoint into a directory of who exists.
                    var known = clients.TryGetValue(tokenRequest.ClientId, out var client) &&
                                CryptographicOperations.FixedTimeEquals(
                                    Encoding.UTF8.GetBytes(client!.ClientSecret),
                                    Encoding.UTF8.GetBytes(tokenRequest.ClientSecret)
                                );

                    if (!known || client is null)
                        return Task.FromResult(
                                   OAuthError(request,
                                              HTTPStatusCode.Unauthorized,
                                              "access_denied",
                                              "Unauthorized")
                               );

                    #endregion

                    #region The token has to be for this deployment

                    if (tokenRequest.Audience != Audience)
                        return Task.FromResult(
                                   OAuthError(request,
                                              HTTPStatusCode.BadRequest,
                                              "invalid_request",
                                              $"This endpoint issues tokens for '{Audience}', not for '{tokenRequest.Audience}'.")
                               );

                    #endregion

                    return Task.FromResult(
                               Respond(request,
                                       HTTPStatusCode.OK,
                                       TokenIssuer.IssueToken(
                                           client.Roles,
                                           client.WMIs,
                                           client.ProviderIds,
                                           client.ClientName,
                                           client.Scopes
                                       ).ToJSON())
                           );

                }
            );

            #endregion

        }

        #endregion

        #region (private) OAuthError(Request, HTTPStatusCode, Error, ErrorDescription)

        /// <summary>
        /// Refuse the way OAuth2 refuses.
        ///
        /// This is the one OPCP endpoint that does not use the specification's own error shape:
        /// accessToken.v1.json defines its failures as an 'error' and an 'error_description',
        /// because it is an OAuth2 endpoint before it is an OPCP one.
        /// </summary>
        private HTTPResponse OAuthError(HTTPRequest     Request,
                                        HTTPStatusCode  HTTPStatusCode,
                                        String          Error,
                                        String?         ErrorDescription)

            => Respond(
                   Request,
                   HTTPStatusCode,
                   new JObject(
                       new JProperty("error",              Error),
                       new JProperty("error_description",  ErrorDescription ?? Error)
                   )
               );

        #endregion

    }

}
