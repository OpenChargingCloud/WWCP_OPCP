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
    /// The certificate a vehicle is born with, together with the sub-CAs that lead to the
    /// manufacturer's root.
    ///
    /// Notably, nothing here says which vehicle: the PUT body has no PCID field, because in
    /// ISO 15118 the PCID <em>is</em> the common name of the provisioning certificate. The pool
    /// reads it from the certificate rather than being told it, so the two can never disagree.
    /// </summary>
    /// <remarks>
    /// One type covers both directions. What the pool returns is what it was given plus what it
    /// worked out while validating - the root the chain anchors to, and the fields derived from
    /// it - so this carries an optional <see cref="RootCertificate"/> that is absent on the way
    /// in and present on the way out.
    ///
    /// <code>
    /// "ProvisioningCertificate": {
    ///   "required": [ "subCA1Certificate", "vehicleCertificate" ],
    ///   "properties": {
    ///     "subCA1Certificate":              { "type": "string" },
    ///     "subCA2Certificate":              { "type": "string" },
    ///     "vehicleCertificate":             { "type": "string" },
    ///     "xsdMsgDefNamespace":             { "enum": [ "urn:iso:15118:2:2013:MsgDef" ] },
    ///     "v2gRootAuthorityKeyIdentifiers": { "type": "array" },
    ///     "previousPcid":                   { "pattern": "^[a-zA-Z0-9]{17,18}$" }
    ///   }
    /// }
    /// </code>
    /// The specification announces that <c>subCA1Certificate</c> will become <c>subCa1Certificate</c>
    /// and <c>vehicleCertificate</c> will become <c>provisioningCertificate</c>. Both spellings are
    /// read; the current ones are written.
    /// </remarks>
    public class ProvisioningCertificate
    {

        #region Data

        private readonly String? rootIssuerDistinguishedName;
        private readonly String? rootIssuerSerialNumber;
        private readonly String? rootAuthorityKeyIdentifier;

        #endregion

        #region Properties

        /// <summary>
        /// The certificate of the vehicle. Its common name is the PCID.
        /// </summary>
        [Mandatory]
        public PnCCertificate               VehicleCertificate                { get; }

        /// <summary>
        /// The intermediate one below the manufacturer's root.
        /// </summary>
        [Mandatory]
        public PnCCertificate               SubCA1Certificate                 { get; }

        /// <summary>
        /// The issuing intermediate, for the manufacturers that use two.
        /// </summary>
        [Optional]
        public PnCCertificate?              SubCA2Certificate                 { get; }

        /// <summary>
        /// The ISO 15118 generation. Only 15118-2 is admitted here today - the enumeration in
        /// the schema has exactly one member, which is what keeps -20 provisioning certificates
        /// out of this pool for now.
        /// </summary>
        [Optional]
        public XSD_MsgDefNamespace?         XSDMsgDefNamespace                { get; }

        /// <summary>
        /// Which V2G roots the vehicle was built trusting, as colon-separated hexadecimal key
        /// identifiers. The manufacturer supplies these; nothing in the certificates says them.
        /// </summary>
        [Optional]
        public IEnumerable<String>          V2GRootAuthorityKeyIdentifiers    { get; }

        /// <summary>
        /// What this vehicle used to be called, when its PCID changed.
        /// </summary>
        [Optional]
        public PCID?                        PreviousPCID                      { get; }

        /// <summary>
        /// The root this chain anchors to. Absent until a pool has validated the chain and
        /// found out.
        /// </summary>
        [Optional]
        public PnCCertificate?              RootCertificate                   { get; }


        /// <summary>
        /// The vehicle this certificate is for, read from the certificate's common name.
        /// Null when the common name is not a PCID at all.
        /// </summary>
        public PCID?                        PCID
            => opcp.PCID.TryParse(VehicleCertificate.CommonName);

        /// <summary>
        /// The intermediates, nearest the vehicle first - the order a chain is walked in.
        /// </summary>
        public IEnumerable<PnCCertificate>  SubCAs
            => SubCA2Certificate is not null
                   ? [ SubCA2Certificate, SubCA1Certificate ]
                   : [ SubCA1Certificate ];


        #region What the pool says about the trust anchor

        // The wire carries these as text, not as the root certificate itself - the recipient is
        // supposed to already have that from the root certificate pool. So a pool derives them
        // from the anchor it established, and a client reads them as the values they are.

        /// <summary>The distinguished name of the trust anchor.</summary>
        public String?  RootIssuerDistinguishedName
            => RootCertificate?.SubjectName ?? rootIssuerDistinguishedName;

        /// <summary>The serial number of the trust anchor, lowercase hexadecimal without separators.</summary>
        public String?  RootIssuerSerialNumber
            => RootCertificate?.SerialNumber ?? rootIssuerSerialNumber;

        /// <summary>The key identifier of the trust anchor, uppercase hexadecimal with colons.</summary>
        public String?  RootAuthorityKeyIdentifier
            => PnCCertificate.ToHex(RootCertificate?.SubjectKeyIdentifier, ":", Uppercase: true)
                   ?? rootAuthorityKeyIdentifier;

        /// <summary>The SHA-256 fingerprint of the vehicle's certificate.</summary>
        public String   Fingerprint
            => VehicleCertificate.SHA256Fingerprint;

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new provisioning certificate chain.
        /// </summary>
        /// <param name="VehicleCertificate">The certificate of the vehicle.</param>
        /// <param name="SubCA1Certificate">The intermediate one below the manufacturer's root.</param>
        /// <param name="SubCA2Certificate">An optional issuing intermediate.</param>
        /// <param name="XSDMsgDefNamespace">An optional ISO 15118 generation.</param>
        /// <param name="V2GRootAuthorityKeyIdentifiers">The V2G roots the vehicle trusts.</param>
        /// <param name="PreviousPCID">What this vehicle used to be called.</param>
        /// <param name="RootCertificate">The trust anchor, once a pool has established it.</param>
        /// <param name="RootIssuerDistinguishedName">What a pool said about the trust anchor, when the anchor itself is not at hand.</param>
        /// <param name="RootIssuerSerialNumber">What a pool said about the trust anchor.</param>
        /// <param name="RootAuthorityKeyIdentifier">What a pool said about the trust anchor.</param>
        public ProvisioningCertificate(PnCCertificate        VehicleCertificate,
                                       PnCCertificate        SubCA1Certificate,
                                       PnCCertificate?       SubCA2Certificate                = null,
                                       XSD_MsgDefNamespace?  XSDMsgDefNamespace               = null,
                                       IEnumerable<String>?  V2GRootAuthorityKeyIdentifiers   = null,
                                       PCID?                 PreviousPCID                     = null,
                                       PnCCertificate?       RootCertificate                  = null,
                                       String?               RootIssuerDistinguishedName      = null,
                                       String?               RootIssuerSerialNumber           = null,
                                       String?               RootAuthorityKeyIdentifier       = null)
        {

            this.rootIssuerDistinguishedName  = RootIssuerDistinguishedName;
            this.rootIssuerSerialNumber       = RootIssuerSerialNumber;
            this.rootAuthorityKeyIdentifier   = RootAuthorityKeyIdentifier;

            this.VehicleCertificate              = VehicleCertificate ?? throw new ArgumentNullException(nameof(VehicleCertificate));
            this.SubCA1Certificate               = SubCA1Certificate  ?? throw new ArgumentNullException(nameof(SubCA1Certificate));
            this.SubCA2Certificate               = SubCA2Certificate;
            this.XSDMsgDefNamespace              = XSDMsgDefNamespace;
            this.V2GRootAuthorityKeyIdentifiers  = V2GRootAuthorityKeyIdentifiers?.
                                                       Where   (identifier => identifier.IsNotNullOrEmpty()).
                                                       Distinct().
                                                       ToArray() ?? [];
            this.PreviousPCID                    = PreviousPCID;
            this.RootCertificate                 = RootCertificate;

        }

        #endregion


        #region WithRoot(RootCertificate)

        /// <summary>
        /// Return this chain as a pool holds it: with the trust anchor it was found to have.
        /// </summary>
        /// <param name="RootCertificate">The trust anchor.</param>
        public ProvisioningCertificate WithRoot(PnCCertificate RootCertificate)

            => new (VehicleCertificate,
                    SubCA1Certificate,
                    SubCA2Certificate,
                    XSDMsgDefNamespace,
                    V2GRootAuthorityKeyIdentifiers,
                    PreviousPCID,
                    RootCertificate);

        #endregion

        #region HasSameKeyAs(Other)

        /// <summary>
        /// Whether the vehicle's key is the same one.
        ///
        /// This is what decides whether re-publishing a vehicle's certificate is a routine update
        /// or the workshop case: a new key pair means every contract issued against the old one is
        /// worthless, and the specification has the pool delete them.
        /// </summary>
        /// <param name="Other">Another provisioning certificate chain.</param>
        public Boolean HasSameKeyAs(ProvisioningCertificate Other)

            => Other is not null &&
               VehicleCertificate.BouncyCastleCertificate.GetPublicKey().Equals(
                   Other.VehicleCertificate.BouncyCastleCertificate.GetPublicKey()
               );

        #endregion


        #region (static) TryParse(JSON, out ProvisioningCertificate, out ErrorResponse, CustomProvisioningCertificateParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of a provisioning certificate chain.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="ProvisioningCertificate">The parsed chain.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomProvisioningCertificateParser">An optional delegate to parse custom chains.</param>
        public static Boolean TryParse(JObject                                                JSON,
                                       [NotNullWhen(true)]  out ProvisioningCertificate?      ProvisioningCertificate,
                                       [NotNullWhen(false)] out String?                       ErrorResponse,
                                       CustomJObjectParserDelegate<ProvisioningCertificate>?  CustomProvisioningCertificateParser   = null)
        {

            try
            {

                ProvisioningCertificate = null;

                #region VehicleCertificate      [mandatory]

                if (!TryReadCertificate(JSON,
                                        [ "vehicleCertificate", "provisioningCertificate" ],
                                        out var vehicleCertificate,
                                        out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region SubCA1Certificate       [mandatory]

                if (!TryReadCertificate(JSON,
                                        [ "subCA1Certificate", "subCa1Certificate" ],
                                        out var subCA1Certificate,
                                        out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region SubCA2Certificate       [optional]

                PnCCertificate? subCA2Certificate = null;

                if (JSON["subCA2Certificate"] is not null || JSON["subCa2Certificate"] is not null)
                {
                    if (!TryReadCertificate(JSON,
                                            [ "subCA2Certificate", "subCa2Certificate" ],
                                            out subCA2Certificate,
                                            out ErrorResponse))
                    {
                        return false;
                    }
                }

                #endregion

                #region XSDMsgDefNamespace      [optional]

                if (JSON.ParseOptional("xsdMsgDefNamespace",
                                       "ISO 15118 message definition namespace",
                                       XSD_MsgDefNamespace.TryParse,
                                       out XSD_MsgDefNamespace? XSDMsgDefNamespace,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region PreviousPCID            [optional]

                if (JSON.ParseOptional("previousPcid",
                                       "previous PCID",
                                       opcp.PCID.TryParse,
                                       out PCID? PreviousPCID,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion


                ProvisioningCertificate = new ProvisioningCertificate(
                                              vehicleCertificate,
                                              subCA1Certificate,
                                              subCA2Certificate,
                                              XSDMsgDefNamespace,
                                              (JSON["v2gRootAuthorityKeyIdentifiers"] as JArray)?.
                                                  Select(token => token.Value<String>() ?? "").
                                                  ToArray(),
                                              PreviousPCID,
                                              null,
                                              JSON.Value<String>("rootIssuerDistinguishedName"),
                                              JSON.Value<String>("rootIssuerSerialNumber"),
                                              JSON.Value<String>("rootAuthorityKeyIdentifier")
                                          );

                if (CustomProvisioningCertificateParser is not null)
                    ProvisioningCertificate = CustomProvisioningCertificateParser(JSON, ProvisioningCertificate);

                return true;

            }
            catch (Exception e)
            {
                ProvisioningCertificate  = null;
                ErrorResponse            = "The given JSON representation of a provisioning certificate is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomProvisioningCertificateSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomProvisioningCertificateSerializer">A delegate to serialize custom chains.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<ProvisioningCertificate>? CustomProvisioningCertificateSerializer = null)
        {

            var json = JSONObject.Create(

                                 new JProperty("vehicleCertificate",                  VehicleCertificate.Base64),
                                 new JProperty("subCA1Certificate",                   SubCA1Certificate. Base64),

                                 SubCA2Certificate is not null
                                     ? new JProperty("subCA2Certificate",             SubCA2Certificate.Base64)
                                     : null,

                                 new JProperty("xsdMsgDefNamespace",                  (XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2).ToString()),

                                 V2GRootAuthorityKeyIdentifiers.Any()
                                     ? new JProperty("v2gRootAuthorityKeyIdentifiers", new JArray(V2GRootAuthorityKeyIdentifiers))
                                     : null,

                                 PreviousPCID.HasValue
                                     ? new JProperty("previousPcid",                  PreviousPCID.Value.ToString())
                                     : null,

                                 // Only a pool that has validated the chain knows these; a
                                 // client that was told them passes them on unchanged.
                                 RootIssuerDistinguishedName is not null
                                     ? new JProperty("rootIssuerDistinguishedName",   RootIssuerDistinguishedName)
                                     : null,

                                 RootIssuerSerialNumber is not null
                                     ? new JProperty("rootIssuerSerialNumber",        RootIssuerSerialNumber)
                                     : null,

                                 RootAuthorityKeyIdentifier is not null
                                     ? new JProperty("rootAuthorityKeyIdentifier",    RootAuthorityKeyIdentifier)
                                     : null,

                                 RootIssuerDistinguishedName is not null
                                     ? new JProperty("fingerprint",                   Fingerprint)
                                     : null

                       );

            return CustomProvisioningCertificateSerializer is not null
                       ? CustomProvisioningCertificateSerializer(this, json)
                       : json;

        }

        #endregion

        #region (private, static) TryReadCertificate(JSON, PropertyNames, out Certificate, out ErrorResponse)

        /// <summary>
        /// Read a certificate that the specification is in the middle of renaming.
        /// </summary>
        private static Boolean TryReadCertificate(JObject                                   JSON,
                                                  String[]                                  PropertyNames,
                                                  [NotNullWhen(true)]  out PnCCertificate?  Certificate,
                                                  [NotNullWhen(false)] out String?          ErrorResponse)
        {

            Certificate    = null;
            ErrorResponse  = null;

            var text = PropertyNames.Select(name => JSON.Value<String>(name)).
                                     FirstOrDefault(value => value.IsNotNullOrEmpty());

            if (text.IsNullOrEmpty())
            {
                ErrorResponse = $"The '{PropertyNames[0]}' is missing!";
                return false;
            }

            if (!PnCCertificate.TryParse(text!, out Certificate, out var certificateError))
            {
                // The specification's own wording for this, from its 400 examples.
                ErrorResponse = $"Invalid certificate format on {PropertyNames[0]}: {certificateError}";
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

            => $"provisioning certificate for {PCID?.ToString() ?? VehicleCertificate.CommonName}";

        #endregion

    }


    /// <summary>
    /// The wrapper the Provisioning Certificate Pool puts around its answer: a provisioning
    /// certificate comes back inside an <c>OEMMessage</c> object. PascalCase in an otherwise
    /// camelCase protocol, and one of the exceptions the specification's own naming rules admit to.
    /// </summary>
    public static class PCPEnvelope
    {

        /// <summary>The property a provisioning certificate is returned under.</summary>
        public const String OEMMessage = "OEMMessage";


        /// <summary>
        /// Wrap a provisioning certificate as getOEMProvCert returns it.
        /// </summary>
        /// <param name="ProvisioningCertificate">A provisioning certificate chain.</param>
        public static JObject Wrap(ProvisioningCertificate ProvisioningCertificate)

            => new (new JProperty(OEMMessage, ProvisioningCertificate.ToJSON()));


        /// <summary>
        /// Read the provisioning certificate out of a getOEMProvCert response.
        /// </summary>
        /// <param name="JSON">The JSON body of the response.</param>
        /// <param name="ProvisioningCertificate">The parsed chain.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryUnwrap(JObject                       JSON,
                                        out ProvisioningCertificate?  ProvisioningCertificate,
                                        out String?                   ErrorResponse)
        {

            // A pool that answered with the bare object rather than the envelope is still
            // answering; there is nothing to gain by refusing to understand it.
            var inner = JSON[OEMMessage] as JObject ?? JSON;

            return opcp.ProvisioningCertificate.TryParse(inner, out ProvisioningCertificate, out ErrorResponse);

        }

    }

}
