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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Talks to a webhook service: what a partner uses to say where it wants to be told about
    /// things, and which things.
    /// </summary>
    public class Webhook_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP Webhook HTTP Client";

        /// <summary>
        /// The path the webhook operations live under.
        /// </summary>
        public const String URLPrefix = "/v1/webhook";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for a webhook service.
        /// </summary>
        /// <param name="RemoteURL">The base URL of the OPCP ecosystem.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="Description">An optional description of this client.</param>
        /// <param name="HTTPUserAgent">An optional HTTP user agent.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="TLSProtocols">The optional TLS protocols to allow.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        /// <param name="MaxNumberOfRetries">The optional maximum number of transmission retries.</param>
        /// <param name="DisableLogging">Whether to disable logging.</param>
        public Webhook_HTTPClient(URL                                                        RemoteURL,
                                  IAccessTokenProvider?                                      AccessTokenProvider          = null,
                                  I18NString?                                                Description                  = null,
                                  String?                                                    HTTPUserAgent                = null,
                                  RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                                  SslProtocols?                                              TLSProtocols                 = null,
                                  TimeSpan?                                                  RequestTimeout               = null,
                                  UInt16?                                                    MaxNumberOfRetries           = null,
                                  Boolean?                                                   DisableLogging               = null)

            : base(RemoteURL,
                   AccessTokenProvider,
                   Description,
                   HTTPUserAgent ?? DefaultHTTPUserAgent,
                   RemoteCertificateValidator,
                   TLSProtocols,
                   RequestTimeout,
                   MaxNumberOfRetries,
                   DisableLogging)

        { }


        /// <summary>
        /// Create a new client for the webhook service of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public Webhook_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                                  IAccessTokenProvider?                                      AccessTokenProvider          = null,
                                  RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                                  TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region CreateEndpoint(Endpoint, ...)

        /// <summary>
        /// Register an endpoint to be told about events.
        /// </summary>
        /// <param name="Endpoint">Where the events should go, and which ones.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <returns>The endpoint as the service recorded it - including the signing secret, which
        /// is the one thing a partner cannot compute for itself.</returns>
        public Task<OPCPResponse<WebhookEndpoint>> CreateEndpoint(WebhookEndpoint    Endpoint,
                                                                  EventTracking_Id?  EventTrackingId     = null,
                                                                  CancellationToken  CancellationToken   = default)

            => Query<WebhookEndpoint>(
                   HTTPMethod.POST,
                   PathOf($"{URLPrefix}/endpoints"),
                   WebhookEndpoint.TryParse,
                   Endpoint.ToJSON(WithSecret: false),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );


        /// <summary>
        /// Register an endpoint to be told about the given events.
        /// </summary>
        /// <param name="URL">Where the events should go.</param>
        /// <param name="EnabledEvents">Which events.</param>
        /// <param name="Description">What this endpoint is for.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<WebhookEndpoint>> CreateEndpoint(URL                       URL,
                                                                  WebhookEventType[]        EnabledEvents,
                                                                  String?                   Description         = null,
                                                                  EventTracking_Id?         EventTrackingId     = null,
                                                                  CancellationToken         CancellationToken   = default)

            => CreateEndpoint(
                   new WebhookEndpoint(
                       URL,
                       EnabledEvents,
                       Description: Description
                   ),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion

        #region GetEndpoints  (...)

        /// <summary>
        /// Ask which endpoints this partner has registered.
        /// </summary>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<IEnumerable<WebhookEndpoint>>> GetEndpoints(EventTracking_Id?  EventTrackingId     = null,
                                                                             CancellationToken  CancellationToken   = default)

            => Query<IEnumerable<WebhookEndpoint>>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/endpoints"),
                   (JObject json, out IEnumerable<WebhookEndpoint>? data, out String? errorResponse) => {

                       data           = null;
                       errorResponse  = null;

                       // A bare array is what the interface document describes; the wrapped one
                       // is what this library's own service answers with, so that the shape of a
                       // list response matches the rest of OPCP. Both are read.
                       var array     = json["endpoints"] as JArray;
                       var endpoints = new List<WebhookEndpoint>();

                       foreach (var token in (array ?? []).OfType<JObject>())
                       {

                           if (!WebhookEndpoint.TryParse(token, out var endpoint, out errorResponse))
                               return false;

                           endpoints.Add(endpoint);

                       }

                       data = endpoints;
                       return true;

                   },
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region GetEndpoint   (Id, ...)

        /// <summary>
        /// Ask about one endpoint.
        /// </summary>
        /// <param name="Id">The endpoint.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<WebhookEndpoint>> GetEndpoint(Webhook_Id         Id,
                                                               EventTracking_Id?  EventTrackingId     = null,
                                                               CancellationToken  CancellationToken   = default)

            => Query<WebhookEndpoint>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/endpoints/{Id}"),
                   WebhookEndpoint.TryParse,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region UpdateEndpoint(Id, Endpoint, ...)

        /// <summary>
        /// Change where an endpoint points, which events it wants, or whether it wants any.
        /// </summary>
        /// <param name="Id">The endpoint.</param>
        /// <param name="Endpoint">What it should become.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<WebhookEndpoint>> UpdateEndpoint(Webhook_Id         Id,
                                                                   WebhookEndpoint    Endpoint,
                                                                   EventTracking_Id?  EventTrackingId     = null,
                                                                   CancellationToken  CancellationToken   = default)

            => Query<WebhookEndpoint>(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/endpoints/{Id}"),
                   WebhookEndpoint.TryParse,
                   Endpoint.ToJSON(WithSecret: false),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region DeleteEndpoint(Id, ...)

        /// <summary>
        /// Stop being told about anything at this endpoint.
        /// </summary>
        /// <param name="Id">The endpoint.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse> DeleteEndpoint(Webhook_Id         Id,
                                                 EventTracking_Id?  EventTrackingId     = null,
                                                 CancellationToken  CancellationToken   = default)

            => Command(
                   HTTPMethod.DELETE,
                   PathOf($"{URLPrefix}/endpoints/{Id}"),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

    }

}
