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
    /// One certificate a contract provisioning service can sign with, and the V2G root it chains
    /// up to.
    ///
    /// A mobility operator reads this list before it asks for a signature: a vehicle will only
    /// accept contract data whose signature chains to a root that vehicle trusts, so the operator
    /// picks the root and names it in the request.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This carries no private key and has nowhere to put one. What is published is exactly what
    /// an operator needs in order to check a signature it will later receive.
    /// </para>
    /// <code>
    /// "cpsSigner-data": {
    ///   "required": [ "cpsDistinguishedName", "cpsCertificate", "validFrom", "validTo",
    ///                 "organizationName", "cpsV2GRootCertificateFingerprint",
    ///                 "cpsRootDistinguishedName", "cpsSubCa1Certificate", "xsdMsgDefNamespace" ],
    ///   "properties": {
    ///     "cpsCertificate":       { "maxLength": 800 },
    ///     "cpsSubCa1Certificate": { "maxLength": 800 },
    ///     "cpsSubCa2Certificate": { "maxLength": 800 }   // optional
    ///   }
    /// }
    /// </code>
    /// <para>
    /// The schema and the example beside it disagree about three names: the example writes
    /// <c>cpsRootCertificateId</c> where the schema has <c>cpsV2GRootCertificateFingerprint</c>,
    /// and <c>cpsCa1Certificate</c> / <c>cpsCa2Certificate</c> where the schema has
    /// <c>cpsSubCa1Certificate</c> / <c>cpsSubCa2Certificate</c>. All six spellings are read; the
    /// schema's are written.
    /// </para>
    /// <para>
    /// The fingerprint field carries a UUID pattern in the schema while its own description calls
    /// it a SHA-256 fingerprint, and the example is a UUID. A SHA-256 fingerprint is what actually
    /// identifies a root, so that is what is written here and what is compared - and any text is
    /// accepted on the way in, because an ecosystem that hands out UUIDs is naming its roots in a
    /// way that is not this library's to correct.
    /// </para>
    /// </remarks>
    public class CpsSigner
    {

        #region Properties

        /// <summary>
        /// The signing certificate.
        /// </summary>
        [Mandatory]
        public PnCCertificate        Certificate                        { get; }

        /// <summary>
        /// The intermediate one below the V2G root.
        /// </summary>
        [Optional]
        public PnCCertificate?       SubCA1Certificate                  { get; }

        /// <summary>
        /// The issuing intermediate, for the hierarchies that use two.
        /// </summary>
        [Optional]
        public PnCCertificate?       SubCA2Certificate                  { get; }

        /// <summary>
        /// The V2G root this signer chains up to, identified as the specification identifies it.
        /// </summary>
        [Mandatory]
        public String                CpsV2GRootCertificateFingerprint   { get; }

        /// <summary>
        /// The distinguished name of that root.
        /// </summary>
        [Mandatory]
        public String                CpsRootDistinguishedName           { get; }

        /// <summary>
        /// The ISO 15118 generation this signer is for.
        /// </summary>
        [Mandatory]
        public XSD_MsgDefNamespace   XSDMsgDefNamespace                 { get; }


        #region Derived from the certificate

        /// <summary>The distinguished name of the signer.</summary>
        public String                CpsDistinguishedName
            => Certificate.SubjectName;

        /// <summary>The organization named in it.</summary>
        public String?               OrganizationName
            => Certificate.Organization;

        /// <summary>The beginning of the validity period.</summary>
        public DateTimeOffset        ValidFrom
            => Certificate.NotBefore;

        /// <summary>The end of it. After this, an operator has to ask for a different signer.</summary>
        public DateTimeOffset        ValidTo
            => Certificate.NotAfter;

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new contract provisioning signer.
        /// </summary>
        /// <param name="Certificate">The signing certificate.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">The V2G root it chains up to.</param>
        /// <param name="CpsRootDistinguishedName">The distinguished name of that root.</param>
        /// <param name="SubCA1Certificate">The intermediate one below the root.</param>
        /// <param name="SubCA2Certificate">An optional issuing intermediate.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        public CpsSigner(PnCCertificate        Certificate,
                         String                CpsV2GRootCertificateFingerprint,
                         String                CpsRootDistinguishedName,
                         PnCCertificate?       SubCA1Certificate                  = null,
                         PnCCertificate?       SubCA2Certificate                  = null,
                         XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null)
        {

            this.Certificate                       = Certificate ?? throw new ArgumentNullException(nameof(Certificate));
            this.CpsV2GRootCertificateFingerprint  = CpsV2GRootCertificateFingerprint;
            this.CpsRootDistinguishedName          = CpsRootDistinguishedName;
            this.SubCA1Certificate                 = SubCA1Certificate;
            this.SubCA2Certificate                 = SubCA2Certificate;
            this.XSDMsgDefNamespace                = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;

        }

        #endregion


        #region (static) From(Signer, XSDMsgDefNamespace = null)

        /// <summary>
        /// Describe an issued signing certificate as the discovery interface publishes it.
        ///
        /// Everything but the ISO generation is read off the certificate and the path it was
        /// issued along, so a published signer cannot describe itself incorrectly.
        /// </summary>
        /// <param name="Signer">A signing certificate, together with the path it was issued along.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        public static CpsSigner From(IssuedCertificate     Signer,
                                     XSD_MsgDefNamespace?  XSDMsgDefNamespace   = null)
        {

            // Nearest the signer first, as the specification lists them: Sub-CA 2, then Sub-CA 1.
            var subCAs = Signer.SubCAs.ToArray();

            return new CpsSigner(
                       Signer.Certificate,
                       Signer.Root.Certificate.SHA256Fingerprint,
                       Signer.Root.Certificate.SubjectName,
                       subCAs.Length > 0 ? subCAs[^1] : null,
                       subCAs.Length > 1 ? subCAs[0]  : null,
                       XSDMsgDefNamespace
                   );

        }

        #endregion

        #region (static) TryParse(JSON, out CpsSigner, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of a contract provisioning signer.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="CpsSigner">The parsed signer.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                             JSON,
                                       [NotNullWhen(true)]  out CpsSigner? CpsSigner,
                                       [NotNullWhen(false)] out String?    ErrorResponse)
        {

            CpsSigner      = null;
            ErrorResponse  = null;

            try
            {

                #region Certificate           [mandatory]

                var certificateText = JSON.Value<String>("cpsCertificate");

                if (certificateText.IsNullOrEmpty())
                {
                    ErrorResponse = "The 'cpsCertificate' is missing!";
                    return false;
                }

                if (!PnCCertificate.TryParse(certificateText!, out var certificate, out var why))
                {
                    ErrorResponse = $"Invalid certificate format on cpsCertificate: {why}";
                    return false;
                }

                #endregion

                #region The intermediates     [optional, under either spelling]

                if (!TryReadCertificate(JSON, "cpsSubCa1Certificate", "cpsCa1Certificate", out var subCA1, out ErrorResponse))
                    return false;

                if (!TryReadCertificate(JSON, "cpsSubCa2Certificate", "cpsCa2Certificate", out var subCA2, out ErrorResponse))
                    return false;

                #endregion

                #region XSDMsgDefNamespace    [optional here, although the schema requires it]

                // The specification's own example of this object omits it.
                var xsdMsgDefNamespace = XSD_MsgDefNamespace.TryParse(JSON.Value<String>("xsdMsgDefNamespace") ?? "");

                #endregion


                CpsSigner = new CpsSigner(
                                certificate,
                                JSON.Value<String>("cpsV2GRootCertificateFingerprint")
                                    ?? JSON.Value<String>("cpsRootCertificateId")
                                    ?? "",
                                JSON.Value<String>("cpsRootDistinguishedName") ?? "",
                                subCA1,
                                subCA2,
                                xsdMsgDefNamespace
                            );

                return true;

            }
            catch (Exception e)
            {
                CpsSigner      = null;
                ErrorResponse  = "The given JSON representation of a contract provisioning signer is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        public JObject ToJSON()

            => JSONObject.Create(

                   new JProperty("cpsDistinguishedName",                   CpsDistinguishedName),
                   new JProperty("cpsCertificate",                         Certificate.Base64),
                   new JProperty("validFrom",                              ValidFrom.ToISO8601(false)),
                   new JProperty("validTo",                                ValidTo.  ToISO8601(false)),

                   OrganizationName.IsNotNullOrEmpty()
                       ? new JProperty("organizationName",                 OrganizationName)
                       : null,

                   new JProperty("cpsV2GRootCertificateFingerprint",       CpsV2GRootCertificateFingerprint),
                   new JProperty("cpsRootDistinguishedName",               CpsRootDistinguishedName),

                   SubCA1Certificate is not null
                       ? new JProperty("cpsSubCa1Certificate",             SubCA1Certificate.Base64)
                       : null,

                   SubCA2Certificate is not null
                       ? new JProperty("cpsSubCa2Certificate",             SubCA2Certificate.Base64)
                       : null,

                   new JProperty("xsdMsgDefNamespace",                     XSDMsgDefNamespace.ToString())

               );

        #endregion


        #region (private, static) TryReadCertificate(JSON, PropertyName, AlternativeName, out Certificate, out ErrorResponse)

        /// <summary>
        /// Read an optional certificate written under either of the two names the specification
        /// uses for it.
        /// </summary>
        private static Boolean TryReadCertificate(JObject                           JSON,
                                                  String                            PropertyName,
                                                  String                            AlternativeName,
                                                  out PnCCertificate?               Certificate,
                                                  [NotNullWhen(false)] out String?  ErrorResponse)
        {

            Certificate    = null;
            ErrorResponse  = null;

            var text = JSON.Value<String>(PropertyName) ?? JSON.Value<String>(AlternativeName);

            if (text.IsNullOrEmpty())
                return true;

            if (!PnCCertificate.TryParse(text!, out Certificate, out var why))
            {
                ErrorResponse = $"Invalid certificate format on {PropertyName}: {why}";
                return false;
            }

            return true;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{Certificate.CommonName} under {CpsRootDistinguishedName}, valid until {ValidTo:yyyy-MM-dd}";

        #endregion

    }


    /// <summary>
    /// The wrapper the signer discovery interface puts around its answer.
    ///
    /// Keeping it here rather than in <see cref="CpsSigner"/> means the client and the API hand
    /// each other signers, and the one place that knows about the envelope is the one place that
    /// has to.
    /// </summary>
    public static class CPSEnvelope
    {

        #region Data

        /// <summary>The array the signers are returned in.</summary>
        public const String CpsCertificates = "cpsCertificates";

        #endregion


        #region WrapMany(Signers)

        /// <summary>
        /// Wrap the signers as getAllCpsSigners returns them.
        /// </summary>
        /// <param name="Signers">An enumeration of signers.</param>
        public static JObject WrapMany(IEnumerable<CpsSigner> Signers)

            => new (
                   new JProperty(CpsCertificates,
                                 new JArray(Signers.Select(signer => signer.ToJSON())))
               );

        #endregion

        #region TryUnwrapMany(JSON, out Signers, out ErrorResponse)

        /// <summary>
        /// Read the signers out of a getAllCpsSigners response.
        /// </summary>
        /// <param name="JSON">The JSON body of the response.</param>
        /// <param name="Signers">The parsed signers.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryUnwrapMany(JObject                          JSON,
                                            out CpsSigner[]?                 Signers,
                                            [NotNullWhen(false)] out String? ErrorResponse)
        {

            Signers        = null;
            ErrorResponse  = null;

            if (JSON[CpsCertificates] is not JArray array)
            {
                ErrorResponse = $"The response carries no '{CpsCertificates}' array!";
                return false;
            }

            var signers = new List<CpsSigner>();

            foreach (var token in array.OfType<JObject>())
            {

                if (!CpsSigner.TryParse(token, out var signer, out ErrorResponse))
                    return false;

                signers.Add(signer);

            }

            Signers = [.. signers];
            return true;

        }

        #endregion

    }

}
