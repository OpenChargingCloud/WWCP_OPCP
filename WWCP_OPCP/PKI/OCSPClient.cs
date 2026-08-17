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

using Org.BouncyCastle.Ocsp;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// What a responder said about a certificate.
    /// </summary>
    public enum OCSPCertificateStatus
    {

        /// <summary>The certificate has not been revoked.</summary>
        Good,

        /// <summary>The certificate has been revoked.</summary>
        Revoked,

        /// <summary>The responder could not say - which is not the same as "good".</summary>
        Unknown

    }


    /// <summary>
    /// The outcome of a revocation check.
    /// </summary>
    /// <param name="Status">What the responder said.</param>
    /// <param name="Reason">In words, particularly when the answer was Unknown.</param>
    /// <param name="RevokedAt">When it was revoked, if it was.</param>
    /// <param name="RevocationReason">Why it was revoked, if a reason was given.</param>
    public sealed record OCSPResult(OCSPCertificateStatus  Status,
                                    String                 Reason,
                                    DateTimeOffset?        RevokedAt          = null,
                                    RevocationReason?      RevocationReason   = null)
    {

        /// <summary>Whether the certificate is usable.</summary>
        public Boolean IsGood     => Status == OCSPCertificateStatus.Good;

        /// <summary>Whether the certificate has been revoked.</summary>
        public Boolean IsRevoked  => Status == OCSPCertificateStatus.Revoked;

        /// <summary>The certificate has not been revoked.</summary>
        public static OCSPResult Good()
            => new (OCSPCertificateStatus.Good, "good");

        /// <summary>Nothing could be established.</summary>
        /// <param name="Reason">Why not.</param>
        public static OCSPResult Unknown(String Reason)
            => new (OCSPCertificateStatus.Unknown, Reason);

    }


    /// <summary>
    /// Asks a responder whether a certificate is still good.
    ///
    /// This is the client half of RFC 6960. The V2G PKI's responders take these unauthenticated,
    /// which is why this client carries no token: a revocation check that needed one would fail
    /// exactly when a compromised credential made it matter.
    /// </summary>
    public class OCSPClient : AOPCPHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP OCSP Client";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OCSP client.
        /// </summary>
        /// <param name="ResponderURL">The URL of the responder.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        public OCSPClient(URL        ResponderURL,
                          TimeSpan?  RequestTimeout   = null)

            : base(ResponderURL,
                   null,   // responders answer unauthenticated
                   null,
                   DefaultHTTPUserAgent,
                   RequestTimeout: RequestTimeout)

        { }

        #endregion


        #region CheckStatus(Certificate, Issuer, ...)

        /// <summary>
        /// Ask whether the given certificate has been revoked.
        /// </summary>
        /// <param name="Certificate">The certificate to ask about.</param>
        /// <param name="Issuer">The authority that issued it.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        /// <remarks>
        /// Anything that goes wrong - an unreachable responder, an unsigned answer, an answer
        /// about a different certificate - comes back as Unknown with a reason, never as Good.
        /// Deciding what to do about not knowing belongs to the caller: the specification has the
        /// pools refuse, and a caller that treated silence as approval would have no revocation
        /// checking at all.
        /// </remarks>
        public async Task<OCSPResult> CheckStatus(PnCCertificate      Certificate,
                                                  PnCCertificate      Issuer,
                                                  EventTracking_Id?   EventTrackingId     = null,
                                                  CancellationToken   CancellationToken   = default)
        {

            try
            {

                #region Ask

                var certificateID  = OCSPResponder.CertificateIDOf(Certificate, Issuer);

                var generator      = new OcspReqGenerator();
                generator.AddRequest(certificateID);

                var httpResponse   = await RunRequest(
                                               HTTPMethod.POST,
                                               RemoteURL.Path,
                                               Content:            generator.Generate().GetEncoded(),
                                               ContentType:        OPCPContentTypes.OCSPRequest,
                                               EventTrackingId:    EventTrackingId,
                                               CancellationToken:  CancellationToken
                                           ).ConfigureAwait(false);

                if (!IsSuccessful(httpResponse.HTTPStatusCode))
                    return OCSPResult.Unknown($"The responder answered HTTP {httpResponse.HTTPStatusCode.Code}.");

                if (httpResponse.HTTPBody is null || httpResponse.HTTPBody.Length == 0)
                    return OCSPResult.Unknown("The responder answered with an empty body.");

                #endregion

                #region Read

                var ocspResponse = new OcspResp(httpResponse.HTTPBody);

                if (ocspResponse.Status != OcspRespStatus.Successful)
                    return OCSPResult.Unknown($"The responder answered with status {ocspResponse.Status}.");

                if (ocspResponse.GetResponseObject() is not BasicOcspResp basicResponse)
                    return OCSPResult.Unknown("The responder's answer carried no data.");

                #endregion

                #region Believe it only if the issuer signed it

                if (!basicResponse.Verify(Issuer.BouncyCastleCertificate.GetPublicKey()))
                    return OCSPResult.Unknown("The responder's answer is not signed by the issuing authority.");

                #endregion

                #region And only if it is about the certificate that was asked about

                var single = basicResponse.Responses.FirstOrDefault(response => response.GetCertID().Equals(certificateID));

                if (single is null)
                    return OCSPResult.Unknown("The responder answered about a different certificate.");

                #endregion

                var status = single.GetCertStatus();

                // BouncyCastle spells "good" as a null status.
                if (status is null)
                    return OCSPResult.Good();

                if (status is RevokedStatus revoked)
                    return new OCSPResult(
                               OCSPCertificateStatus.Revoked,
                               "revoked",
                               new DateTimeOffset(revoked.RevocationTime.ToUniversalTime(), TimeSpan.Zero),
                               revoked.HasRevocationReason
                                   ? (RevocationReason) revoked.RevocationReason
                                   : null
                           );

                return OCSPResult.Unknown("The responder does not know this certificate.");

            }
            catch (Exception e)
            {
                return OCSPResult.Unknown($"The revocation check failed: {e.Message}");
            }

        }

        #endregion

    }

}
