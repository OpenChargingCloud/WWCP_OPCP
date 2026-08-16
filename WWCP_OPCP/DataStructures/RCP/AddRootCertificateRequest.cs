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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Admitting a root CA certificate into the Root Certificate Pool.
    ///
    /// The pool derives everything it publishes about a root from the certificate, so this
    /// carries only what it cannot: the certificate, and which trust domain it anchors.
    /// </summary>
    /// <remarks>
    /// <code>
    /// { "caCertificate": "MIICTTCCAfOg...",   // base64 DER, maxLength 800
    ///   "rootType":      "V2G" }              // MO | V2G | OEM | PE
    /// </code>
    /// Getting here is the small half of admitting a root. The other half is organizational and
    /// outside this protocol: the certificate arrives out of band, its fingerprint is confirmed
    /// over a second channel, and only then does an administrator make this call.
    /// </remarks>
    public class AddRootCertificateRequest
    {

        #region Data

        /// <summary>
        /// The longest base64 the specification accepts for a certificate. ISO 15118 constrains
        /// how large a certificate may be, and the pools state that constraint on the field.
        /// </summary>
        public const Int32 MaxCertificateLength = 800;

        #endregion

        #region Properties

        /// <summary>
        /// The certificate to admit.
        /// </summary>
        [Mandatory]
        public PnCCertificate       Certificate    { get; }

        /// <summary>
        /// Which trust domain it anchors.
        /// </summary>
        [Mandatory]
        public RootCertificateType  RootType       { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new request to admit a root CA certificate.
        /// </summary>
        /// <param name="Certificate">The certificate to admit.</param>
        /// <param name="RootType">Which trust domain it anchors.</param>
        public AddRootCertificateRequest(PnCCertificate       Certificate,
                                         RootCertificateType  RootType)
        {

            this.Certificate  = Certificate ?? throw new ArgumentNullException(nameof(Certificate));
            this.RootType     = RootType;

        }

        #endregion


        #region (static) TryParse(JSON, out Request, out ErrorResponse, CustomAddRootCertificateRequestParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of a request to admit a root CA certificate.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="Request">The parsed request.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomAddRootCertificateRequestParser">An optional delegate to parse custom requests.</param>
        public static Boolean TryParse(JObject                                                  JSON,
                                       [NotNullWhen(true)]  out AddRootCertificateRequest?      Request,
                                       [NotNullWhen(false)] out String?                         ErrorResponse,
                                       CustomJObjectParserDelegate<AddRootCertificateRequest>?  CustomAddRootCertificateRequestParser   = null)
        {

            try
            {

                Request = null;

                #region CACertificate    [mandatory]

                if (!JSON.ParseMandatoryText("caCertificate",
                                             "CA certificate",
                                             out String? CACertificate,
                                             out ErrorResponse))
                {
                    return false;
                }

                if (!PnCCertificate.TryParse(CACertificate, out var certificate, out var certificateError))
                {
                    ErrorResponse = $"The given CA certificate is invalid: {certificateError}";
                    return false;
                }

                #endregion

                #region RootType         [mandatory]

                if (!JSON.ParseMandatory("rootType",
                                         "root certificate type",
                                         RootCertificateType.TryParse,
                                         out RootCertificateType RootType,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion


                Request = new AddRootCertificateRequest(
                              certificate,
                              RootType
                          );

                if (CustomAddRootCertificateRequestParser is not null)
                    Request = CustomAddRootCertificateRequestParser(JSON, Request);

                return true;

            }
            catch (Exception e)
            {
                Request        = null;
                ErrorResponse  = "The given JSON representation of a root certificate request is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomAddRootCertificateRequestSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomAddRootCertificateRequestSerializer">A delegate to serialize custom requests.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<AddRootCertificateRequest>? CustomAddRootCertificateRequestSerializer = null)
        {

            var json = JSONObject.Create(
                           new JProperty("caCertificate",  Certificate.Base64),
                           new JProperty("rootType",       RootType.ToString())
                       );

            return CustomAddRootCertificateRequestSerializer is not null
                       ? CustomAddRootCertificateRequestSerializer(this, json)
                       : json;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"admit '{Certificate.CommonName}' as a {RootType} root";

        #endregion

    }

}
