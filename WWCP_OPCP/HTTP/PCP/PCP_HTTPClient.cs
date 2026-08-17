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
    /// Talks to a Provisioning Certificate Pool.
    ///
    /// Vehicle manufacturers publish here, one vehicle at a time, and mobility operators read -
    /// this is where an operator gets the certificate it needs to conclude a contract with a car
    /// it has never seen.
    /// </summary>
    public class PCP_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP PCP HTTP Client";

        /// <summary>
        /// The path all Provisioning Certificate Pool operations live under.
        /// </summary>
        public const String URLPrefix = "/v1/oem";

        /// <summary>
        /// Set on a request that must not be forwarded to other ecosystems.
        /// </summary>
        public const String BroadcastHeader = "broadcast";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for a Provisioning Certificate Pool.
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
        public PCP_HTTPClient(URL                                                        RemoteURL,
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
        /// Create a new client for the Provisioning Certificate Pool of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public PCP_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                              IAccessTokenProvider?                                      AccessTokenProvider          = null,
                              RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                              TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region AddOEMProvCert   (Certificate, ...)

        /// <summary>
        /// Publish the certificate a vehicle was born with.
        ///
        /// Which vehicle is not stated anywhere in the request: the pool reads the PCID from the
        /// certificate's common name. Publishing again for the same vehicle replaces what was
        /// there - and if the vehicle's key changed with it, the contracts issued against the old
        /// key are deleted, because none of them can be used any more.
        /// </summary>
        /// <param name="Certificate">The chain to publish.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<ProvisioningCertificate>> AddOEMProvCert(ProvisioningCertificate  Certificate,
                                                                          EventTracking_Id?        EventTrackingId     = null,
                                                                          CancellationToken        CancellationToken   = default)

            => Query<ProvisioningCertificate>(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/provCerts"),
                   PCPEnvelope.TryUnwrap,
                   Certificate.ToJSON(),
                   PayloadRequired:    false,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region GetOEMProvCert   (PCID, Broadcast = null, ...)

        /// <summary>
        /// Fetch the certificate a vehicle was born with.
        ///
        /// The pool re-checks the chain and its revocation status before handing it over, so a
        /// certificate that has become unusable since it was published is not served.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="Broadcast">When true, the request is not forwarded to other ecosystems.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<ProvisioningCertificate>> GetOEMProvCert(PCID                PCID,
                                                                          Boolean?            Broadcast           = null,
                                                                          EventTracking_Id?   EventTrackingId     = null,
                                                                          CancellationToken   CancellationToken   = default)

            => Query<ProvisioningCertificate>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/provCerts/{PCID}"),
                   PCPEnvelope.TryUnwrap,
                   RequestBuilder: Broadcast.HasValue
                                       ? builder => builder.SetHeaderField(BroadcastHeader, Broadcast.Value ? "true" : "false")
                                       : null,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region DeleteOEMProvCert(PCID, ...)

        /// <summary>
        /// Depublish the certificate of a vehicle.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// This reaches further than it looks. A successful delete has the contract certificate
        /// pool delete every contract belonging to this vehicle, and contracts issued by an
        /// operator-owned certification authority are revoked as well - a vehicle whose
        /// provisioning certificate is gone can no longer prove it is the car those contracts
        /// were written for.
        /// </remarks>
        public Task<OPCPResponse> DeleteOEMProvCert(PCID                PCID,
                                                    EventTracking_Id?   EventTrackingId     = null,
                                                    CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.DELETE,
                   PathOf($"{URLPrefix}/provCerts/{PCID}"),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region LookupVehicle    (PCID, ...)

        /// <summary>
        /// Ask whether the pool knows this vehicle at all, without fetching anything.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// A GET that answers with a status and no body. The specification notes this will become
        /// a HEAD on the certificate itself in a future version, which is what it should have been.
        /// </remarks>
        public Task<OPCPResponse> LookupVehicle(PCID                PCID,
                                                EventTracking_Id?   EventTrackingId     = null,
                                                CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/provCerts/lookupVehicle/{PCID}"),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

    }

}
