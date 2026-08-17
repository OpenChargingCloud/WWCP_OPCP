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

using System.Diagnostics;
using System.Security.Authentication;
using System.Text;

using Org.BouncyCastle.Pkcs;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Talks to the enrollment interface of a V2G PKI service.
    ///
    /// This is where the certificates of the whole ecosystem come from. A charging station asks
    /// for the one it authenticates to vehicles with, a manufacturer for the one a car is born
    /// with, a mobility operator for a contract's, a provisioning service for the one it signs
    /// contract data with - all of them the same way, and all of them from a different authority
    /// below the same V2G root.
    /// </summary>
    /// <remarks>
    /// The one part of OPCP that is not a JSON protocol: RFC 7030 sends a PKCS#10 certificate
    /// signing request up and gets a certificates-only PKCS#7 back, both base64-encoded.
    /// </remarks>
    public class EST_HTTPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP EST HTTP Client";

        /// <summary>
        /// Where RFC 7030 puts an enrollment service.
        /// </summary>
        public const String URLPrefix = "/.well-known/est";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new client for the enrollment interface of a V2G PKI service.
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
        public EST_HTTPClient(URL                                                        RemoteURL,
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
        /// Create a new client for the enrollment interface of the given ecosystem.
        /// </summary>
        /// <param name="EndpointConfig">Which ecosystem to talk to.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public EST_HTTPClient(OPCPEndpointConfig                                         EndpointConfig,
                              IAccessTokenProvider?                                      AccessTokenProvider          = null,
                              RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                              TimeSpan?                                                  RequestTimeout               = null)

            : this(EndpointConfig.BaseURL,
                   AccessTokenProvider,
                   RemoteCertificateValidator:  RemoteCertificateValidator,
                   RequestTimeout:              RequestTimeout)

        { }

        #endregion


        #region SimpleEnroll(CA, CSR, XSDMsgDefNamespace = null, ...)

        /// <summary>
        /// Ask an authority to turn a certificate signing request into a certificate.
        /// </summary>
        /// <param name="CA">Which authority - and therefore what kind of certificate.</param>
        /// <param name="CSR">The certificate signing request.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <returns>The issued certificate first, and the authorities above it behind it.</returns>
        /// <remarks>
        /// The common name of the request is the whole of what is being asked for: in ISO 15118 it
        /// is the identifier itself, and an authority refuses a request whose common name is not
        /// the kind of identifier it certifies.
        /// </remarks>
        public Task<OPCPResponse<IEnumerable<PnCCertificate>>> SimpleEnroll(CA_Id                       CA,
                                                                            Pkcs10CertificationRequest  CSR,
                                                                            XSD_MsgDefNamespace?        XSDMsgDefNamespace   = null,
                                                                            EventTracking_Id?           EventTrackingId      = null,
                                                                            CancellationToken           CancellationToken    = default)
        {

            var isoVersion = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;

            return Enroll(
                       HTTPMethod.POST,
                       PathOf($"{URLPrefix}/{CA}/simpleenroll/{isoVersion.ToISOVersion()}"),
                       Encoding.ASCII.GetBytes(CSR.ToBase64()),
                       OPCPContentTypes.PKCS10,
                       QueryString.Empty.Add("xsdMsgDefNamespace", isoVersion.ToString()),
                       EventTrackingId,
                       CancellationToken
                   );

        }

        #endregion

        #region CACerts     (CA, Algorithm = null, XSDMsgDefNamespace = null, ...)

        /// <summary>
        /// Ask an authority for the chain above it, so that what it issues can be verified.
        /// </summary>
        /// <param name="CA">Which authority.</param>
        /// <param name="Algorithm">Which curve's hierarchy.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <returns>The chain, nearest the leaves first.</returns>
        /// <remarks>
        /// This is the one operation of the enrollment service the specification writes without
        /// the <c>/.well-known/est</c> prefix RFC 7030 gives it. That path is the one used here,
        /// because it is the one the interface document states.
        /// </remarks>
        public Task<OPCPResponse<IEnumerable<PnCCertificate>>> CACerts(CA_Id                 CA,
                                                                       SignatureAlgorithm?   Algorithm            = null,
                                                                       XSD_MsgDefNamespace?  XSDMsgDefNamespace   = null,
                                                                       EventTracking_Id?     EventTrackingId      = null,
                                                                       CancellationToken     CancellationToken    = default)

            => Enroll(
                   HTTPMethod.GET,
                   PathOf($"/{CA}/cacerts/{(XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2).ToISOVersion()}/{Algorithm ?? SignatureAlgorithm.secp256r1}/"),
                   null,
                   null,
                   null,
                   EventTrackingId,
                   CancellationToken
               );

        #endregion


        #region (private) Enroll(HTTPMethod, Path, Content, ContentType, QueryString, EventTrackingId, CancellationToken)

        /// <summary>
        /// Send one enrollment request and read the certificates that came back.
        /// </summary>
        private async Task<OPCPResponse<IEnumerable<PnCCertificate>>> Enroll(HTTPMethod         HTTPMethod,
                                                                             HTTPPath           Path,
                                                                             Byte[]?            Content,
                                                                             HTTPContentType?   ContentType,
                                                                             QueryString?       QueryString,
                                                                             EventTracking_Id?  EventTrackingId,
                                                                             CancellationToken  CancellationToken)
        {

            var eventTrackingId  = EventTrackingId ?? EventTracking_Id.New;
            var startTime        = DateTimeOffset.UtcNow;
            var stopwatch        = Stopwatch.StartNew();

            try
            {

                var httpResponse = await Send(
                                             HTTPMethod,
                                             Path,
                                             Content,
                                             ContentType,
                                             AcceptTypes.FromHTTPContentTypes(
                                                 OPCPContentTypes.PKCS7Mime,
                                                 OPCPContentTypes.PKCS7
                                             ),
                                             QueryString,
                                             // RFC 7030 sends the structure base64-encoded and
                                             // says so in a header rather than in the media type.
                                             builder => builder.Set("Content-Transfer-Encoding", "base64"),
                                             eventTrackingId,
                                             CancellationToken
                                         ).ConfigureAwait(false);

                stopwatch.Stop();

                if (!IsSuccessful(httpResponse.HTTPStatusCode))
                    return OPCPResponse<IEnumerable<PnCCertificate>>.Failed(
                               ParseError(httpResponse),
                               httpResponse.HTTPStatusCode,
                               startTime,
                               stopwatch.Elapsed,
                               eventTrackingId,
                               httpResponse
                           );

                var body = httpResponse.HTTPBodyAsUTF8String?.Trim();

                if (body.IsNullOrEmpty())
                    return OPCPResponse<IEnumerable<PnCCertificate>>.Failed(
                               OPCPError.Create("The enrollment service answered with an empty body!"),
                               httpResponse.HTTPStatusCode,
                               startTime,
                               stopwatch.Elapsed,
                               eventTrackingId,
                               httpResponse
                           );

                if (!Pkcs7CertificateContainer.TryParse(body!, out var certificates, out var errorResponse))
                    return OPCPResponse<IEnumerable<PnCCertificate>>.Failed(
                               OPCPError.Create(errorResponse),
                               httpResponse.HTTPStatusCode,
                               startTime,
                               stopwatch.Elapsed,
                               eventTrackingId,
                               httpResponse
                           );

                return OPCPResponse<IEnumerable<PnCCertificate>>.Success(
                           certificates,
                           httpResponse.HTTPStatusCode,
                           startTime,
                           stopwatch.Elapsed,
                           eventTrackingId,
                           httpResponse
                       );

            }
            catch (Exception e)
            {

                stopwatch.Stop();

                return OPCPResponse<IEnumerable<PnCCertificate>>.Failed(
                           OPCPError.Create($"The OPCP request failed: {e.Message}"),
                           HTTPStatusCode.BadGateway,
                           startTime,
                           stopwatch.Elapsed,
                           eventTrackingId
                       );

            }

        }

        #endregion

    }

}
