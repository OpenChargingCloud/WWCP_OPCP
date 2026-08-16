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
    /// Talks to a Root Certificate Pool.
    ///
    /// Everyone in a Plug&amp;Charge ecosystem reads from this pool - it is where the trust anchors
    /// come from - and only an administrator of the ecosystem writes to it.
    /// </summary>
    public class RCP_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP RCP HTTP Client";

        /// <summary>
        /// The path all Root Certificate Pool operations live under.
        /// </summary>
        public const String URLPrefix = "/v1/root";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for a Root Certificate Pool.
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
        public RCP_HTTPClient(URL                                                        RemoteURL,
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
        /// Create a new client for the Root Certificate Pool of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public RCP_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                              IAccessTokenProvider?                                      AccessTokenProvider          = null,
                              RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                              TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region GetRootCert    (RootCertificateId, ...)

        /// <summary>
        /// Return one root certificate.
        /// </summary>
        /// <param name="RootCertificateId">The identification the pool gave the certificate.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<RootCertificate>> GetRootCert(RootCertificate_Id  RootCertificateId,
                                                               EventTracking_Id?   EventTrackingId     = null,
                                                               CancellationToken   CancellationToken   = default)

            => Query<RootCertificate>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/rootCerts/{RootCertificateId}"),
                   RCPEnvelope.TryUnwrapOne,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region GetAllRootCerts(RootType = null, ...)

        /// <summary>
        /// Return the pool's trust anchors, optionally of one trust domain only.
        ///
        /// This is the call participants make regularly: OPCP has no delta, no pagination and no
        /// conditional requests, so keeping up with the pool means asking it for everything.
        /// </summary>
        /// <param name="RootType">An optional trust domain to filter by.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public async Task<OPCPResponse<IEnumerable<RootCertificate>>> GetAllRootCerts(RootCertificateType?  RootType            = null,
                                                                                      EventTracking_Id?     EventTrackingId     = null,
                                                                                      CancellationToken     CancellationToken   = default)
        {

            var response = await Query<RootCertificate[]>(
                                     HTTPMethod.GET,
                                     PathOf($"{URLPrefix}/rootCerts"),
                                     RCPEnvelope.TryUnwrapMany,
                                     QueryString: RootType.HasValue
                                                      // The filter is lowercase while the value inside
                                                      // a certificate is uppercase - the specification
                                                      // spells the same vocabulary both ways.
                                                      ? QueryString.Empty.Add("rootType", RootType.Value.ToString().ToLowerInvariant())
                                                      : null,
                                     EventTrackingId:    EventTrackingId,
                                     CancellationToken:  CancellationToken
                                 ).ConfigureAwait(false);

            return response.Error is not null

                       ? OPCPResponse<IEnumerable<RootCertificate>>.Failed(
                             response.Error,
                             response.HTTPStatusCode,
                             response.Timestamp,
                             response.Runtime,
                             response.EventTrackingId,
                             response.HTTPResponse
                         )

                       : OPCPResponse<IEnumerable<RootCertificate>>.Success(
                             response.Data ?? [],
                             response.HTTPStatusCode,
                             response.Timestamp,
                             response.Runtime,
                             response.EventTrackingId,
                             response.HTTPResponse
                         );

        }

        #endregion

        #region SaveRootCA     (Request, ...)

        /// <summary>
        /// Admit a root CA certificate into the pool. Reserved for an administrator of the ecosystem.
        /// </summary>
        /// <param name="Request">The certificate and the trust domain it anchors.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// The specification documents no response body for this call, so a pool that answers with
        /// one is not obliged to. When it does - as this library's own pool does - the stored entry
        /// comes back with the identification it was given, which is otherwise only discoverable by
        /// listing the pool afterwards.
        /// </remarks>
        public Task<OPCPResponse<RootCertificate>> SaveRootCA(AddRootCertificateRequest  Request,
                                                              EventTracking_Id?          EventTrackingId     = null,
                                                              CancellationToken          CancellationToken   = default)

            => Query<RootCertificate>(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/rootCerts"),
                   RCPEnvelope.TryUnwrapOne,
                   Request.ToJSON(),
                   PayloadRequired:    false,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region SaveRootCA     (Certificate, RootType, ...)

        /// <summary>
        /// Admit a root CA certificate into the pool.
        /// </summary>
        /// <param name="Certificate">The certificate to admit.</param>
        /// <param name="RootType">Which trust domain it anchors.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<RootCertificate>> SaveRootCA(PnCCertificate       Certificate,
                                                              RootCertificateType  RootType,
                                                              EventTracking_Id?    EventTrackingId     = null,
                                                              CancellationToken    CancellationToken   = default)

            => SaveRootCA(
                   new AddRootCertificateRequest(Certificate, RootType),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion

        #region DeleteRootCA   (RootCertificateId, ...)

        /// <summary>
        /// Remove a root certificate from the pool. Reserved for an administrator of the ecosystem.
        /// </summary>
        /// <param name="RootCertificateId">The identification the pool gave the certificate.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// Removing a root does not remove what depends on it. The specification is explicit that
        /// dependent provisioning certificates and contracts must not be cascade-deleted
        /// automatically - what happens to them is an organizational decision, not this call's.
        /// </remarks>
        public Task<OPCPResponse> DeleteRootCA(RootCertificate_Id  RootCertificateId,
                                               EventTracking_Id?   EventTrackingId     = null,
                                               CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.DELETE,
                   PathOf($"{URLPrefix}/rootCerts/{RootCertificateId}"),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region GetCertificateTrustList(...)

        /// <summary>
        /// Download the pool's Certificate Trust List.
        /// </summary>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// This endpoint is a placeholder in OPCP 1.0.0: the specification says its content is
        /// "still to be aligned by stakeholders", and declares a request body on a GET. Until
        /// there is something to model, the raw JSON is returned as it arrives.
        /// </remarks>
        public Task<OPCPResponse<JObject>> GetCertificateTrustList(EventTracking_Id?  EventTrackingId     = null,
                                                                   CancellationToken  CancellationToken   = default)

            => Query<JObject>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/ctl"),
                   (JObject json, out JObject? data, out String? errorResponse) => {
                       data           = json;
                       errorResponse  = null;
                       return true;
                   },
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

    }

}
