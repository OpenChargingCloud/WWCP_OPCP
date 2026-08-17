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
using System.Security.Authentication;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// What the contract certificate pool answered a vehicle's request with.
    /// </summary>
    /// <param name="CertificateInstallationRes">The response to hand back to the vehicle.</param>
    /// <param name="EMAId">The contract that was installed, when one was.</param>
    /// <param name="Metadata">Whatever the operator attached to it.</param>
    /// <param name="CpsV2GRootCertificateFingerprint">The V2G root the signer anchors to.</param>
    /// <param name="Installed">
    /// Whether a contract was actually found. False for the ISO-shaped refusal the pool returns
    /// when a vehicle has no contract - which arrives with HTTP 404 and a readable body, not with
    /// nothing.
    /// </param>
    public sealed record InstalledContract(Byte[]   CertificateInstallationRes,
                                           EMA_Id?  EMAId                              = null,
                                           String?  Metadata                           = null,
                                           String?  CpsV2GRootCertificateFingerprint   = null,
                                           Boolean  Installed                          = true);


    /// <summary>
    /// Talks to a Contract Certificate Pool.
    ///
    /// This is where the Plug&amp;Charge story ends up: a car plugs in, the charging station
    /// forwards its request through the operator's backend to here, and what comes back is the
    /// contract the car will charge under.
    /// </summary>
    public class CCP_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP CCP HTTP Client";

        /// <summary>
        /// The path all Contract Certificate Pool operations live under.
        /// </summary>
        public const String URLPrefix = "/v1/ccp";

        /// <summary>
        /// Ask for an ISO-compliant response even when the answer is "no contract".
        /// </summary>
        public const String AlwaysReturnEXIHeader = "alwaysReturnEXI";

        /// <summary>
        /// Set on a request that must not be forwarded to other ecosystems.
        /// </summary>
        public const String BroadcastHeader = "broadcast";

        /// <summary>
        /// Delete without revoking. For tests only, and the specification says so.
        /// </summary>
        public const String SkipRevocationHeader = "X-Skip-Revocation";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for a Contract Certificate Pool.
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
        public CCP_HTTPClient(URL                                                        RemoteURL,
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
        /// Create a new client for the Contract Certificate Pool of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public CCP_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                              IAccessTokenProvider?                                      AccessTokenProvider          = null,
                              RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                              TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region GetSignedContractData(CertificateInstallationReq, ...)

        /// <summary>
        /// Answer a vehicle's certificate installation request. The hot path of the whole protocol.
        /// </summary>
        /// <param name="CertificateInstallationReq">The request as it came from the vehicle.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="AlwaysReturnEXI">Whether a vehicle with no contract should still get an ISO-shaped answer.</param>
        /// <param name="Broadcast">When true, the request is not forwarded to other ecosystems.</param>
        /// <param name="Metadata">Whatever the operator wants carried along.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// The answer to "this car has no contract" is an HTTP 404 whose body is nevertheless a
        /// perfectly good ISO 15118 response - the charging station relaying it speaks ISO 15118,
        /// not HTTP, and has to be given something it can pass on. So this reads the body on both
        /// the success and the not-found path, and reports which happened through
        /// <see cref="InstalledContract.Installed"/> rather than through the status code alone.
        /// </remarks>
        public async Task<OPCPResponse<InstalledContract>> GetSignedContractData(Byte[]                CertificateInstallationReq,
                                                                                 XSD_MsgDefNamespace?  XSDMsgDefNamespace   = null,
                                                                                 Boolean?              AlwaysReturnEXI      = null,
                                                                                 Boolean?              Broadcast            = null,
                                                                                 String?               Metadata             = null,
                                                                                 EventTracking_Id?     EventTrackingId      = null,
                                                                                 CancellationToken     CancellationToken    = default)
        {

            var startTime  = DateTimeOffset.UtcNow;

            var body       = JSONObject.Create(
                                 new JProperty("certificateInstallationReq",  Convert.ToBase64String(CertificateInstallationReq)),
                                 new JProperty("xsdMsgDefNamespace",          (XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2).ToString()),
                                 Metadata.IsNotNullOrEmpty()
                                     ? new JProperty("metadata",              Metadata)
                                     : null
                             );

            var httpResponse = await Send(
                                         HTTPMethod.POST,
                                         PathOf($"{URLPrefix}/signedContractData"),
                                         body,
                                         RequestBuilder: builder => {

                                             if (AlwaysReturnEXI.HasValue)
                                                 builder.SetHeaderField(AlwaysReturnEXIHeader, AlwaysReturnEXI.Value ? "true" : "false");

                                             if (Broadcast.HasValue)
                                                 builder.SetHeaderField(BroadcastHeader,       Broadcast.Value       ? "true" : "false");

                                         },
                                         EventTrackingId:    EventTrackingId,
                                         CancellationToken:  CancellationToken
                                     ).ConfigureAwait(false);

            var runtime  = DateTimeOffset.UtcNow - startTime;

            #region An ISO-shaped answer, whether or not a contract was found

            if (TryReadJSON(httpResponse, out var json, out _) &&
                TryReadInstalled(json, IsSuccessful(httpResponse.HTTPStatusCode), out var installed))
            {
                return OPCPResponse<InstalledContract>.Success(
                           installed,
                           httpResponse.HTTPStatusCode,
                           startTime,
                           runtime,
                           EventTrackingId,
                           httpResponse
                       );
            }

            #endregion

            return OPCPResponse<InstalledContract>.Failed(
                       ParseError(httpResponse),
                       httpResponse.HTTPStatusCode,
                       startTime,
                       runtime,
                       EventTrackingId,
                       httpResponse
                   );

        }

        #endregion

        #region AddSignedContractData(ContractData, ...)

        /// <summary>
        /// Put a signed contract into the pool, as a contract provisioning service does.
        /// </summary>
        /// <param name="ContractData">The signed contract data.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse> AddSignedContractData(SignedContractData  ContractData,
                                                        EventTracking_Id?   EventTrackingId     = null,
                                                        CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.PUT,
                   PathOf($"{URLPrefix}/signedContractData"),
                   ContractData.ToJSON(),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region DeleteSignedContractData(EMAId, SkipRevocation = null, ...)

        /// <summary>
        /// Delete a contract.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="SkipRevocation">Do not revoke the contract certificate. For tests only.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// A contract certificate issued by an operator-owned authority is revoked before the
        /// contract is deleted, and only a successful revocation lets the delete proceed -
        /// otherwise a certificate would go on being accepted by cars that never hear it is gone.
        /// </remarks>
        public Task<OPCPResponse> DeleteSignedContractData(EMA_Id              EMAId,
                                                           Boolean?            SkipRevocation      = null,
                                                           EventTracking_Id?   EventTrackingId     = null,
                                                           CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.DELETE,
                   PathOf($"{URLPrefix}/signedContractData/{EMAId}"),
                   RequestBuilder: SkipRevocation.HasValue
                                       ? builder => builder.SetHeaderField(SkipRevocationHeader, SkipRevocation.Value ? "true" : "false")
                                       : null,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region ProvideSignedContractData(EMAId, PCID, ...)

        /// <summary>
        /// Fetch a prepared response for one contract, as a vehicle manufacturer's backend does
        /// when it installs a contract over its own channel rather than over a charging station.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="SessionId">An optional ISO 15118 session identification to embed.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// The specification is explicit that what comes back has <em>not</em> had the checks of
        /// [V2G2-894] applied - the manufacturer has to make them itself before handing this to a
        /// car, including whether the contract certificate is still valid and unrevoked.
        /// </remarks>
        public Task<OPCPResponse<InstalledContract>> ProvideSignedContractData(EMA_Id              EMAId,
                                                                               PCID                PCID,
                                                                               String?             SessionId           = null,
                                                                               EventTracking_Id?   EventTrackingId     = null,
                                                                               CancellationToken   CancellationToken   = default)

            => Query<InstalledContract>(
                   HTTPMethod.GET,
                   PathOf($"{URLPrefix}/provideSignedContractData/{EMAId}/{PCID}"),
                   (JObject json, out InstalledContract? data, out String? errorResponse) => {
                       errorResponse = null;
                       return TryReadInstalled(json, true, out data);
                   },
                   QueryString: SessionId.IsNotNullOrEmpty()
                                    ? QueryString.Empty.Add("sessionID", SessionId!)
                                    : null,
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region SetDefaultContract(PCID, EMAId, ...)

        /// <summary>
        /// Make one of a vehicle's contracts the one to install when it expresses no preference.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="EMAId">One of its contracts.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse> SetDefaultContract(PCID                PCID,
                                                     EMA_Id              EMAId,
                                                     EventTracking_Id?   EventTrackingId     = null,
                                                     CancellationToken   CancellationToken   = default)

            => Command(
                   HTTPMethod.POST,
                   PathOf($"{URLPrefix}/signedContractData/{PCID}/{EMAId}/default"),
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region LookupContract(EMAId, ...)

        /// <summary>
        /// Ask what the pool holds for one contract.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<IEnumerable<JObject>>> LookupContract(EMA_Id              EMAId,
                                                                       EventTracking_Id?   EventTrackingId     = null,
                                                                       CancellationToken   CancellationToken   = default)

            => QueryContracts(
                   PathOf($"{URLPrefix}/lookupContract/{EMAId}"),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion

        #region GetContracts(PCID, ...)

        /// <summary>
        /// Ask what contracts a vehicle has.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<OPCPResponse<IEnumerable<JObject>>> GetContracts(PCID                PCID,
                                                                     EventTracking_Id?   EventTrackingId     = null,
                                                                     CancellationToken   CancellationToken   = default)

            => QueryContracts(
                   PathOf($"{URLPrefix}/signedContractData/{PCID}"),
                   EventTrackingId,
                   CancellationToken
               );

        #endregion


        #region (private) QueryContracts(Path, EventTrackingId, CancellationToken)

        private Task<OPCPResponse<IEnumerable<JObject>>> QueryContracts(HTTPPath           Path,
                                                                        EventTracking_Id?  EventTrackingId,
                                                                        CancellationToken  CancellationToken)

            => Query<IEnumerable<JObject>>(
                   HTTPMethod.GET,
                   Path,
                   (JObject json, out IEnumerable<JObject>? data, out String? errorResponse) => {

                       errorResponse = null;

                       data = (json["XMLContracts"] as JArray)?.
                                  OfType<JObject>().
                                  ToArray() ?? [];

                       return true;

                   },
                   EventTrackingId:    EventTrackingId,
                   CancellationToken:  CancellationToken
               );

        #endregion

        #region (private, static) TryReadInstalled(JSON, Successful, out Installed)

        /// <summary>
        /// Read the ISO-shaped answer out of either the success or the not-found body.
        /// </summary>
        private static Boolean TryReadInstalled(JObject                              JSON,
                                                Boolean                              Successful,
                                                [NotNullWhen(true)] out InstalledContract?  Installed)
        {

            Installed = null;

            // The success shape wraps everything twice: CCPResponse, then an array of one entry
            // per contract, each with a messageDef inside it. The array is preparation for
            // ISO 15118-20; for -2 it holds exactly one.
            var messageDef = ((JSON["CCPResponse"]?["emaidContent"] as JArray)?.
                                  OfType<JObject>().
                                  FirstOrDefault())?["messageDef"] as JObject;

            var text       = messageDef?.Value<String>("certificateInstallationRes")
                                 ?? JSON.Value<String>("certificateInstallationRes");

            if (text.IsNullOrEmpty())
                return false;

            try
            {

                Installed = new InstalledContract(
                                Convert.FromBase64String(text!),
                                EMA_Id.TryParse(messageDef?.Value<String>("emaid") ?? ""),
                                messageDef?.Value<String>("metaData"),
                                messageDef?.Value<String>("cpsV2GRootCertificateFingerprint")
                                    ?? JSON.Value<String>("cpsV2GRootCertificateFingerprint"),
                                Successful
                            );

                return true;

            }
            catch
            {
                return false;
            }

        }

        #endregion

    }

}
