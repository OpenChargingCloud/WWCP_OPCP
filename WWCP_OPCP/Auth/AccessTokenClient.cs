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

using System.Security.Authentication;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Asks an OPCP ecosystem for an access token.
    ///
    /// The one OPCP client that carries no bearer token, because obtaining one is what it is for.
    /// It also usually talks to a different host than the services do: the example token of
    /// accessToken.v1.json was issued by <c>auth.eu.plugncharge.hubject.com</c> for services
    /// living at <c>eu.plugncharge-qa.hubject.com</c>.
    /// </summary>
    public class AccessTokenClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP Access Token Client";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new access token client.
        /// </summary>
        /// <param name="TokenEndpoint">The full URL of the OAuth2 token endpoint.</param>
        /// <param name="Description">An optional description of this client.</param>
        /// <param name="HTTPUserAgent">An optional HTTP user agent.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="TLSProtocols">The optional TLS protocols to allow.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        /// <param name="MaxNumberOfRetries">The optional maximum number of transmission retries.</param>
        /// <param name="DisableLogging">Whether to disable logging.</param>
        public AccessTokenClient(URL                                                        TokenEndpoint,
                                 I18NString?                                                Description                  = null,
                                 String?                                                    HTTPUserAgent                = null,
                                 RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                                 SslProtocols?                                              TLSProtocols                 = null,
                                 TimeSpan?                                                  RequestTimeout               = null,
                                 UInt16?                                                    MaxNumberOfRetries           = null,
                                 Boolean?                                                   DisableLogging               = null)

            : base(TokenEndpoint,
                   null,   // obtaining a token is what this client is for
                   Description,
                   HTTPUserAgent ?? DefaultHTTPUserAgent,
                   RemoteCertificateValidator,
                   TLSProtocols,
                   RequestTimeout,
                   MaxNumberOfRetries,
                   DisableLogging)

        { }

        #endregion


        #region IssueToken(Request, ...)

        /// <summary>
        /// Ask for an access token.
        /// </summary>
        /// <param name="Request">The credentials and the deployment to ask for.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<AccessTokenResponse>> IssueToken(AccessTokenRequest  Request,
                                                                  EventTracking_Id?   EventTrackingId     = null,
                                                                  CancellationToken   CancellationToken   = default)

            => Query<AccessTokenResponse>(
                   HTTPMethod.POST,

                   // The endpoint's own path, since the token endpoint is a whole URL rather
                   // than an operation under a base address.
                   RemoteURL.Path,

                   (json, out data, out errorResponse) => AccessTokenResponse.TryParse(json, out data, out errorResponse),
                   Request.ToJSON(),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region IssueToken(ClientId, ClientSecret, Audience, ...)

        /// <summary>
        /// Ask for an access token.
        /// </summary>
        /// <param name="ClientId">The identification of the client.</param>
        /// <param name="ClientSecret">The secret of the client.</param>
        /// <param name="Audience">The stage and world region to ask for.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<AccessTokenResponse>> IssueToken(String              ClientId,
                                                                  String              ClientSecret,
                                                                  URL                 Audience,
                                                                  EventTracking_Id?   EventTrackingId     = null,
                                                                  CancellationToken   CancellationToken   = default)

            => IssueToken(
                   new AccessTokenRequest(ClientId, ClientSecret, Audience),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion


        #region (static) CreateTokenProvider(EndpointConfig, ClientId, ClientSecret, ...)

        /// <summary>
        /// Build a token provider that keeps a token fresh by asking this endpoint for a new one.
        ///
        /// This is the ordinary way to authenticate a client: hand the result to any of the six
        /// service clients and they will carry a valid bearer token without further thought.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to authenticate against.</param>
        /// <param name="ClientId">The identification of the client.</param>
        /// <param name="ClientSecret">The secret of the client.</param>
        /// <param name="SafetyMargin">An optional margin before expiry to renew within.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public static ClientCredentialsTokenProvider CreateTokenProvider(OPCPEndpointConfig                                         EndpointConfig,
                                                                         String                                                     ClientId,
                                                                         String                                                     ClientSecret,
                                                                         TimeSpan?                                                  SafetyMargin                 = null,
                                                                         RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                                                                         TimeSpan?                                                  RequestTimeout               = null)
        {

            var client = new AccessTokenClient(
                             EndpointConfig.TokenEndpoint,
                             RemoteCertificateValidator:  RemoteCertificateValidator,
                             RequestTimeout:              RequestTimeout
                         );

            return new ClientCredentialsTokenProvider(
                       async cancellationToken => {

                           var response = await client.IssueToken(
                                                    ClientId,
                                                    ClientSecret,
                                                    EndpointConfig.Audience,
                                                    CancellationToken: cancellationToken
                                                ).ConfigureAwait(false);

                           // A client that cannot authenticate must fail loudly rather than
                           // carry on unauthenticated and be refused one request at a time.
                           return response.GetDataOrThrow();

                       },
                       SafetyMargin
                   );

        }

        #endregion

    }

}
