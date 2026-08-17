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
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A stand-in for the ISO 15118 codec, so that a whole Plug&amp;Charge ecosystem can be run
    /// and tested without one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is not the ISO 15118 wire format and does not pretend to be.</b> Where ISO 15118
    /// has EXI-encoded messages signed with XMLDSig, this has JSON signed with ECDSA. Every
    /// structural property the pools rely on is preserved - a request names a vehicle and the
    /// roots it trusts, a response carries contract data, signed data is signed by a certificate
    /// and the signature is checked - and no byte of it would mean anything to a real car.
    /// </para>
    /// <para>
    /// The container marks itself as such: every structure it produces carries a <c>_format</c>
    /// property saying what it is, so that one turning up somewhere it should not is recognizable
    /// rather than mysterious.
    /// </para>
    /// </remarks>
    public class TestContractDataCodec : IContractDataCodec
    {

        #region Data

        /// <summary>
        /// What every structure this codec produces says about itself.
        /// </summary>
        public const String FormatMarker = "WWCP-OPCP test container - NOT ISO 15118 wire format";

        #endregion


        #region EncodeInstallationRequest(PCID, RootCertificateIds = null, PrioritizedEMAIds = null, ...)

        /// <summary>
        /// Build what a vehicle would send when it plugs in.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="RootCertificateIds">The V2G roots it trusts.</param>
        /// <param name="PrioritizedEMAIds">The contracts it would prefer.</param>
        /// <param name="MaximumContractCertificateChains">How many contracts it can take.</param>
        public static Byte[] EncodeInstallationRequest(PCID                  PCID,
                                                       IEnumerable<String>?  RootCertificateIds                 = null,
                                                       IEnumerable<EMA_Id>?  PrioritizedEMAIds                  = null,
                                                       Byte                  MaximumContractCertificateChains   = 1)

            => Encoding.UTF8.GetBytes(
                   new JObject(
                       new JProperty("_format",                           FormatMarker),
                       new JProperty("pcid",                              PCID.ToString()),
                       new JProperty("rootCertificateIds",                new JArray(RootCertificateIds ?? [])),
                       new JProperty("prioritizedEMAIds",                 new JArray((PrioritizedEMAIds ?? []).Select(emaId => emaId.ToString()))),
                       new JProperty("maximumContractCertificateChains",  MaximumContractCertificateChains)
                   ).ToString(Formatting.None)
               );

        #endregion

        #region TryDecodeInstallationRequest(Request, out Decoded, out ErrorResponse)

        /// <summary>
        /// Read what a vehicle asked for.
        /// </summary>
        /// <param name="Request">The certificate installation request.</param>
        /// <param name="Decoded">What the vehicle asked for.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        public Boolean TryDecodeInstallationRequest(Byte[]                                                   Request,
                                                    [NotNullWhen(true)]  out CertificateInstallationRequest? Decoded,
                                                    [NotNullWhen(false)] out String?                         ErrorResponse)
        {

            Decoded        = null;
            ErrorResponse  = null;

            try
            {

                var json  = JObject.Parse(Encoding.UTF8.GetString(Request));

                var pcid  = PCID.TryParse(json.Value<String>("pcid") ?? "");

                if (!pcid.HasValue)
                {
                    // The specification's own wording for an unreadable request.
                    ErrorResponse = "EXI format is invalid!";
                    return false;
                }

                Decoded = new CertificateInstallationRequest(
                              pcid.Value,
                              (json["rootCertificateIds"] as JArray)?.
                                  Select(token => token.Value<String>() ?? "").
                                  Where (text  => text.IsNotNullOrEmpty()).
                                  ToArray() ?? [],
                              (json["prioritizedEMAIds"] as JArray)?.
                                  Select(token => EMA_Id.TryParse(token.Value<String>() ?? "")).
                                  Where (emaId => emaId.HasValue).
                                  Select(emaId => emaId!.Value).
                                  ToArray() ?? [],
                              (Byte) (json.Value<Int32?>("maximumContractCertificateChains") ?? 1)
                          );

                return true;

            }
            catch
            {
                ErrorResponse = "EXI format is invalid!";
                return false;
            }

        }

        #endregion


        #region SignContractData(ContractData, EMAId, PCID, SignerCertificate, SigningKey)

        /// <summary>
        /// Sign contract data, as a contract provisioning service does.
        /// </summary>
        /// <param name="ContractData">What is being signed.</param>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle it is for, when it is known.</param>
        /// <param name="SignerCertificate">The certificate the signature is made under.</param>
        /// <param name="SigningKey">The key to sign with.</param>
        public static Byte[] SignContractData(ContractData            ContractData,
                                              EMA_Id                  EMAId,
                                              PCID?                   PCID,
                                              PnCCertificate          SignerCertificate,
                                              AsymmetricKeyParameter  SigningKey)
        {

            var payload    = new JObject(
                                 new JProperty("_format",       FormatMarker),
                                 new JProperty("emaid",         EMAId.ToString()),
                                 new JProperty("pcid",          PCID?.ToString()),
                                 new JProperty("contractData",  ContractData.ToJSON())
                             );

            var canonical  = Encoding.UTF8.GetBytes(payload.ToString(Formatting.None));

            var signer     = SignerUtilities.GetSigner(OCSPResponder.SignatureAlgorithmNameOf(SigningKey));
            signer.Init(true, SigningKey);
            signer.BlockUpdate(canonical, 0, canonical.Length);

            return Encoding.UTF8.GetBytes(
                       new JObject(
                           new JProperty("payload",            Convert.ToBase64String(canonical)),
                           new JProperty("signerCertificate",  SignerCertificate.Base64),
                           new JProperty("signature",          Convert.ToBase64String(signer.GenerateSignature()))
                       ).ToString(Formatting.None)
                   );

        }

        #endregion

        #region (seam) SignContractData(ContractData, EMAId, PCID, SignerCertificate, SigningKey)

        /// <summary>
        /// Sign contract data, as a contract provisioning service does.
        /// </summary>
        /// <param name="ContractData">What is being signed.</param>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle it is for, when it is known.</param>
        /// <param name="SignerCertificate">The certificate the signature is made under.</param>
        /// <param name="SigningKey">The key to sign with.</param>
        /// <remarks>
        /// Explicitly implemented, because a type cannot carry a static and an instance method of
        /// the same signature - and the static one above is what a test ecosystem calls directly,
        /// without going through the seam.
        /// </remarks>
        Byte[] IContractDataCodec.SignContractData(ContractData            ContractData,
                                                   EMA_Id                  EMAId,
                                                   PCID?                   PCID,
                                                   PnCCertificate          SignerCertificate,
                                                   AsymmetricKeyParameter  SigningKey)

            => TestContractDataCodec.SignContractData(ContractData,
                                                      EMAId,
                                                      PCID,
                                                      SignerCertificate,
                                                      SigningKey);

        #endregion

        #region VerifySignedContractData(SignedContractData, out SignerCertificate, out ErrorResponse)

        /// <summary>
        /// Check that signed contract data really was signed by the certificate it names.
        /// </summary>
        /// <param name="SignedContractData">The signed contract data.</param>
        /// <param name="SignerCertificate">The certificate it was signed under.</param>
        /// <param name="ErrorResponse">Why it was not acceptable.</param>
        public static Boolean VerifySignedContractData(Byte[]                                    SignedContractData,
                                                       [NotNullWhen(true)]  out PnCCertificate?  SignerCertificate,
                                                       [NotNullWhen(false)] out String?          ErrorResponse)
        {

            SignerCertificate  = null;
            ErrorResponse      = null;

            try
            {

                var json = JObject.Parse(Encoding.UTF8.GetString(SignedContractData));

                if (!PnCCertificate.TryParse(json.Value<String>("signerCertificate") ?? "", out var certificate, out var why))
                {
                    ErrorResponse = $"The signed contract data names no readable signer certificate: {why}";
                    return false;
                }

                var canonical  = Convert.FromBase64String(json.Value<String>("payload")   ?? "");
                var signature  = Convert.FromBase64String(json.Value<String>("signature") ?? "");

                var verifier   = SignerUtilities.GetSigner(certificate.BouncyCastleCertificate.SigAlgName);
                verifier.Init(false, certificate.BouncyCastleCertificate.GetPublicKey());
                verifier.BlockUpdate(canonical, 0, canonical.Length);

                if (!verifier.VerifySignature(signature))
                {
                    ErrorResponse = "The signature of the signed contract data is invalid!";
                    return false;
                }

                SignerCertificate = certificate;
                return true;

            }
            catch (Exception e)
            {
                ErrorResponse = "The signed contract data could not be read: " + e.Message;
                return false;
            }

        }

        #endregion

        #region TryReadSignedContractData(SignedContractData, out ContractData, out ErrorResponse)

        /// <summary>
        /// Read the contract data out of what was signed - after checking the signature, because
        /// reading unverified data and acting on it would defeat the point of signing it.
        /// </summary>
        /// <param name="SignedContractData">The signed contract data.</param>
        /// <param name="ContractData">What it contains.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        public Boolean TryReadSignedContractData(Byte[]                                  SignedContractData,
                                                 [NotNullWhen(true)]  out ContractData?  ContractData,
                                                 [NotNullWhen(false)] out String?        ErrorResponse)
        {

            ContractData = null;

            if (!VerifySignedContractData(SignedContractData, out _, out ErrorResponse))
                return false;

            try
            {

                var outer    = JObject.Parse(Encoding.UTF8.GetString(SignedContractData));
                var payload  = JObject.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(outer.Value<String>("payload") ?? "")));

                if (payload["contractData"] is not JObject contractData)
                {
                    ErrorResponse = "The signed contract data carries no contract data!";
                    return false;
                }

                return opcp.ContractData.TryParse(contractData, out ContractData, out ErrorResponse);

            }
            catch (Exception e)
            {
                ErrorResponse = "The signed contract data could not be read: " + e.Message;
                return false;
            }

        }

        #endregion

        #region TryEncodeInstallationResponse(SignedContractData, out Response, out ErrorResponse)

        /// <summary>
        /// Turn signed contract data into the response that goes back to the vehicle.
        /// </summary>
        /// <param name="SignedContractData">The signed contract data.</param>
        /// <param name="Response">The certificate installation response.</param>
        /// <param name="ErrorResponse">Why it could not be produced.</param>
        public Boolean TryEncodeInstallationResponse(Byte[]                            SignedContractData,
                                                     [NotNullWhen(true)]  out Byte[]?  Response,
                                                     [NotNullWhen(false)] out String?  ErrorResponse)
        {

            Response = null;

            // The pool does not re-sign anything: what the contract provisioning service signed
            // is what the vehicle has to verify, so it travels unchanged inside the response.
            if (!VerifySignedContractData(SignedContractData, out _, out ErrorResponse))
                return false;

            Response = Encoding.UTF8.GetBytes(
                           new JObject(
                               new JProperty("_format",             FormatMarker),
                               new JProperty("responseCode",        "OK"),
                               new JProperty("signedContractData",  Convert.ToBase64String(SignedContractData))
                           ).ToString(Formatting.None)
                       );

            return true;

        }

        #endregion

        #region EncodeNegativeResponse(Reason)

        /// <summary>
        /// A response saying that nothing could be installed.
        /// </summary>
        /// <param name="Reason">Why nothing could be installed.</param>
        public Byte[] EncodeNegativeResponse(String Reason)

            => Encoding.UTF8.GetBytes(
                   new JObject(
                       new JProperty("_format",       FormatMarker),
                       new JProperty("responseCode",  "FAILED"),
                       new JProperty("reason",        Reason)
                   ).ToString(Formatting.None)
               );

        #endregion

    }

}
