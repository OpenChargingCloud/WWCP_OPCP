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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Builds the PKCS#10 certificate signing requests that enrollment is made of.
    ///
    /// Everything that gets a certificate from the V2G PKI asks for it this way: a charging
    /// station for its own, a vehicle manufacturer for a vehicle's, a mobility operator for a
    /// contract's. The request says who the subject is and proves possession of the private key
    /// by signing itself with it.
    /// </summary>
    /// <remarks>
    /// Hermod can sign a certificate signing request but not create one, so this is written here
    /// against BouncyCastle. The common name is the whole of the interesting content: in
    /// ISO 15118 it is the identifier - a PCID, an EMAID, an EVSEID - and the certification
    /// authority refuses a request whose common name is not the identifier it was asked to certify.
    /// </remarks>
    public static class CSRBuilder
    {

        #region Create(CommonName, KeyPair, Organization = null, Country = null)

        /// <summary>
        /// Create and sign a certificate signing request.
        /// </summary>
        /// <param name="CommonName">The subject - in ISO 15118, the identifier itself.</param>
        /// <param name="KeyPair">The key the certificate is being asked for.</param>
        /// <param name="Organization">The legal name of the organization asking.</param>
        /// <param name="Country">An optional ISO 3166-1 alpha-2 country code.</param>
        public static Pkcs10CertificationRequest Create(String                   CommonName,
                                                        AsymmetricCipherKeyPair  KeyPair,
                                                        String?                  Organization   = null,
                                                        String?                  Country        = null)
        {

            if (CommonName.IsNullOrEmpty())
                throw new ArgumentException("The given common name must not be null or empty!", nameof(CommonName));

            var oids    = new List<DerObjectIdentifier> { X509Name.CN };
            var values  = new List<String>              { CommonName };

            if (Organization.IsNotNullOrEmpty())
            {
                oids.  Add(X509Name.O);
                values.Add(Organization!);
            }

            if (Country.IsNotNullOrEmpty())
            {
                oids.  Add(X509Name.C);
                values.Add(Country!);
            }

            return new Pkcs10CertificationRequest(
                       new Asn1SignatureFactory(
                           OCSPResponder.SignatureAlgorithmNameOf(KeyPair.Private),
                           KeyPair.Private
                       ),
                       new X509Name(oids, values),
                       KeyPair.Public,
                       null
                   );

        }

        #endregion

        #region CreateFor(PCID | EMAId, KeyPair, ...)

        /// <summary>
        /// Ask for the certificate a vehicle will be born with.
        /// </summary>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="KeyPair">The vehicle's key.</param>
        /// <param name="Organization">The manufacturer's legal name.</param>
        /// <param name="Country">An optional country code.</param>
        public static Pkcs10CertificationRequest CreateFor(PCID                     PCID,
                                                           AsymmetricCipherKeyPair  KeyPair,
                                                           String?                  Organization   = null,
                                                           String?                  Country        = null)

            => Create(PCID.ToString(), KeyPair, Organization, Country);

        /// <summary>
        /// Ask for a contract certificate.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="KeyPair">The contract's key.</param>
        /// <param name="Organization">The operator's legal name.</param>
        /// <param name="Country">An optional country code.</param>
        public static Pkcs10CertificationRequest CreateFor(EMA_Id                   EMAId,
                                                           AsymmetricCipherKeyPair  KeyPair,
                                                           String?                  Organization   = null,
                                                           String?                  Country        = null)

            => Create(EMAId.ToString(), KeyPair, Organization, Country);

        #endregion


        #region ToBase64  (CSR)

        /// <summary>
        /// The base64-encoded DER of a request, which is how enrollment transports it.
        /// </summary>
        /// <param name="CSR">A certificate signing request.</param>
        public static String ToBase64(this Pkcs10CertificationRequest CSR)

            => Convert.ToBase64String(CSR.GetEncoded());

        #endregion

        #region TryParse  (Base64, out CSR, out ErrorResponse)

        /// <summary>
        /// Read a base64-encoded certificate signing request, and check that it signed itself.
        /// </summary>
        /// <param name="Base64">The base64-encoded DER of a request.</param>
        /// <param name="CSR">The parsed request.</param>
        /// <param name="ErrorResponse">Why it could not be read or was not acceptable.</param>
        public static Boolean TryParse(String                                                Base64,
                                       [NotNullWhen(true)]  out Pkcs10CertificationRequest?  CSR,
                                       [NotNullWhen(false)] out String?                      ErrorResponse)
        {

            CSR            = null;
            ErrorResponse  = null;

            var text = Base64?.Trim() ?? "";

            if (text.IsNullOrEmpty())
            {
                ErrorResponse = "The given certificate signing request must not be null or empty!";
                return false;
            }

            try
            {

                var csr = new Pkcs10CertificationRequest(Convert.FromBase64String(text));

                // A request signs itself with the key it is asking about. Without that check the
                // request would prove nothing: anyone could ask for a certificate on a public key
                // they do not hold the private half of.
                if (!csr.Verify())
                {
                    ErrorResponse = "The given certificate signing request is not signed by the key it asks about!";
                    return false;
                }

                CSR = csr;
                return true;

            }
            catch (Exception e)
            {
                ErrorResponse = "The given certificate signing request could not be read: " + e.Message;
                return false;
            }

        }

        #endregion

        #region GetCommonName(CSR)

        /// <summary>
        /// The common name a request asks for - the ISO 15118 identifier it wants certified.
        /// </summary>
        /// <param name="CSR">A certificate signing request.</param>
        public static String GetCommonName(this Pkcs10CertificationRequest CSR)

            => PKIFactory.GetCommonName(CSR.GetCertificationRequestInfo().Subject);

        #endregion

    }

}
