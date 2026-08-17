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
    /// Talks to a Certificate Provisioning Service.
    ///
    /// This is what a mobility operator uses: it hands over a contract it has issued - or, without
    /// a PKI of its own, describes one - and gets back something a vehicle will accept, because
    /// the contract certificate pool takes contract data only from a signer it trusts.
    /// </summary>
    public class CPS_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP CPS HTTP Client";

        /// <summary>
        /// The path the Certificate Provisioning Service operations live under.
        /// </summary>
        public const String URLPrefix = "/v1/cps";

        /// <summary>
        /// Where the signers are listed.
        /// </summary>
        /// <remarks>
        /// Without the version prefix every other operation of this service carries. That is the
        /// specification's own path and not a transcription error - and because it is plainly one
        /// of its inconsistencies, an implementation of this service is also expected to answer at
        /// <c>/v1/cps/signer</c>, which is what <see cref="CPS_HTTPAPI"/> does.
        /// </remarks>
        public const String SignerPath = "/cps/signer";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for a Certificate Provisioning Service.
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
        public CPS_HTTPClient(URL                                                        RemoteURL,
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
        /// Create a new client for the Certificate Provisioning Service of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public CPS_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                              IAccessTokenProvider?                                      AccessTokenProvider          = null,
                              RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                              TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region SignContractData(Request, ...)

        /// <summary>
        /// Have contract data signed, and - if the request names a vehicle - filed in the contract
        /// certificate pool.
        /// </summary>
        /// <param name="Request">The contract data to sign.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// Naming a vehicle is the whole difference between this and the two deprecated operations
        /// it replaces: with a PCID it signs and files, without one it only signs.
        /// </remarks>
        public Task<OPCPResponse<SignedContractDataResponse>> SignContractData(SignedContractDataRequest  Request,
                                                                               EventTracking_Id?          EventTrackingId     = null,
                                                                               CancellationToken          CancellationToken   = default)

            => Query<SignedContractDataResponse>(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/contractData/signed"),
                   SignedContractDataResponse.TryParse,
                   Request.ToJSON(),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );


        /// <summary>
        /// Have contract data signed, and - if a vehicle is named - filed in the contract
        /// certificate pool.
        /// </summary>
        /// <param name="ContractData">The contract certificate, its chain and the wrapped key.</param>
        /// <param name="PCID">An optional vehicle - naming one asks for the result to be filed.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">An optional V2G root to anchor the signature to.</param>
        /// <param name="Metadata">Whatever should be carried along.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<SignedContractDataResponse>> SignContractData(ContractData          ContractData,
                                                                               PCID?                 PCID                               = null,
                                                                               XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                                                               String?               CpsV2GRootCertificateFingerprint   = null,
                                                                               String?               Metadata                           = null,
                                                                               EventTracking_Id?     EventTrackingId                    = null,
                                                                               CancellationToken     CancellationToken                  = default)

            => SignContractData(
                   new SignedContractDataRequest(
                       ContractData,
                       XSDMsgDefNamespace,
                       PCID,
                       null,
                       Metadata,
                       CpsV2GRootCertificateFingerprint
                   ),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion

        #region CreateSignedContractData(Request, ...)                [deprecated]

        /// <summary>
        /// Have contract data signed and nothing else - the operator files the result itself.
        /// </summary>
        /// <param name="Request">The contract data to sign.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// Deprecated by the specification and still operated, which is why it is here. It differs
        /// from its replacement in the shape of the contract data it takes - the nested one - and
        /// in never filing anything.
        /// </remarks>
        [Obsolete("Deprecated by the specification. Use SignContractData without a PCID instead.")]
        public Task<OPCPResponse<SignedContractDataResponse>> CreateSignedContractData(SignedContractDataRequest  Request,
                                                                                        EventTracking_Id?          EventTrackingId     = null,
                                                                                        CancellationToken          CancellationToken   = default)

            => Query<SignedContractDataResponse>(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/signedContractData"),
                   SignedContractDataResponse.TryParse,
                   Request.ToJSON(Nested: true),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region CreateAndForwardSignedContractData(Request, ...)      [deprecated]

        /// <summary>
        /// Have contract data signed and filed in the contract certificate pool.
        /// </summary>
        /// <param name="Request">The contract data to sign.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// Deprecated by the specification and still operated. Its replacement does the same thing
        /// when the request names a vehicle, and answers with the signature rather than with an
        /// empty body.
        /// </remarks>
        [Obsolete("Deprecated by the specification. Use SignContractData with a PCID instead.")]
        public Task<OPCPResponse> CreateAndForwardSignedContractData(SignedContractDataRequest  Request,
                                                                     EventTracking_Id?          EventTrackingId     = null,
                                                                     CancellationToken          CancellationToken   = default)

            => Command(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/forward/signedContractData"),
                   Request.ToJSON(Nested: true),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region GenerateSignedContractData(Request, ...)

        /// <summary>
        /// Have a contract issued, signed and filed - the path for a mobility operator without a
        /// PKI of its own.
        /// </summary>
        /// <param name="Request">What the contract is to say.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// The vehicle has to be in the provisioning certificate pool already, because the
        /// contract's private key is wrapped against the key in its certificate. Calling this
        /// again for the same vehicle and contract replaces what was filed before.
        /// </remarks>
        public Task<OPCPResponse> GenerateSignedContractData(GenerateSignedContractDataRequest  Request,
                                                             EventTracking_Id?                  EventTrackingId     = null,
                                                             CancellationToken                  CancellationToken   = default)

            => Command(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/generate/signedContractData"),
                   Request.ToJSON(),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );


        /// <summary>
        /// Have a contract issued, signed and filed.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle it is for.</param>
        /// <param name="ContractBegins">When the contract starts.</param>
        /// <param name="ContractEnds">When it ends.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">An optional V2G root to anchor the signature to.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse> GenerateSignedContractData(EMA_Id                EMAId,
                                                             PCID                  PCID,
                                                             DateTimeOffset        ContractBegins,
                                                             DateTimeOffset        ContractEnds,
                                                             XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                                             String?               CpsV2GRootCertificateFingerprint   = null,
                                                             EventTracking_Id?     EventTrackingId                    = null,
                                                             CancellationToken     CancellationToken                  = default)

            => GenerateSignedContractData(
                   new GenerateSignedContractDataRequest(
                       EMAId,
                       PCID,
                       ContractBegins,
                       ContractEnds,
                       XSDMsgDefNamespace,
                       null,
                       CpsV2GRootCertificateFingerprint
                   ),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion

        #region GetAllCpsSigners(...)

        /// <summary>
        /// Ask which certificates this service can sign with, and which V2G roots they chain up to.
        /// </summary>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// A mobility operator reads this before it asks for a signature: a vehicle accepts only a
        /// signature that chains to a root it trusts, so the operator picks the root here and names
        /// it in the request.
        /// </remarks>
        public Task<OPCPResponse<IEnumerable<CpsSigner>>> GetAllCpsSigners(EventTracking_Id?  EventTrackingId     = null,
                                                                           CancellationToken  CancellationToken   = default)

            => Query<IEnumerable<CpsSigner>>(
                   HTTPMethod.GET,
                   PathOf(SignerPath),
                   (JObject json, out IEnumerable<CpsSigner>? data, out String? errorResponse) => {

                       var read = CPSEnvelope.TryUnwrapMany(json, out var signers, out errorResponse);

                       data = signers;
                       return read;

                   },
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

    }

}
