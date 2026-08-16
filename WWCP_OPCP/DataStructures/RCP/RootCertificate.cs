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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A root CA certificate as the Root Certificate Pool holds it.
    ///
    /// Only three things about an entry are not in the certificate: the identification the pool
    /// assigned it, which trust domain it anchors, and a handful of pointers the operator may
    /// have been given alongside it. Everything else the pool publishes - the distinguished name,
    /// the common name, the organization, the serial number, the key identifier in its two
    /// encodings, the validity, both fingerprints, the curve - is read from the certificate
    /// rather than stored beside it, so that no entry can describe itself incorrectly.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "RootCertV2": {
    ///   "title": "Root Cert (V2)",
    ///   "required": [ "rootType", "caCertificate" ],
    ///   "properties": {
    ///     "rootCertificateId":             { "type": "string", "format": "uuid" },
    ///     "distinguishedName":             { "type": "string" },
    ///     "rootType":                      { "enum": [ "MO", "V2G", "OEM", "PE" ] },
    ///     "caCertificate":                 { "type": "string", "maxLength": 800 },
    ///     "commonName":                    { "type": "string" },
    ///     "rootAuthorityKeyIdentifier":    { "type": "string" },
    ///     "rootAuthorityKeyIdentifierHex": { "type": "string" },
    ///     "rootIssuerSerialNumber":        { "type": "string" },
    ///     "validFrom":                     { "format": "date-time" },
    ///     "validTo":                       { "format": "date-time" },
    ///     "organizationName":              { "type": "string" },
    ///     "certificateRevocationList":     { "type": "string" },
    ///     "crossCertificatePair":          { "type": "string" },
    ///     "labeledUri":                    { "type": "string" },
    ///     "fingerprint":                   { "type": "string" },
    ///     "fingerprintSha1":               { "type": "string" },
    ///     "xsdMsgDefNamespace":            { "enum": [ ... ] },
    ///     "signatureAlgorithm":            { "enum": [ "secp256r1", "secp521r1", "ed448" ] }
    ///   }
    /// }
    /// </code>
    /// The schema also carries <c>"minProperties": 1, "maxProperties": 1</c>, which would forbid
    /// an object from having more than one property and is plainly a mistake - every example in
    /// the same document violates it. It is ignored.
    /// </remarks>
    public class RootCertificate : IEquatable<RootCertificate>
    {

        #region Properties

        /// <summary>
        /// The identification the pool assigned this entry. Absent on an entry that has not
        /// been stored yet.
        /// </summary>
        [Optional]
        public RootCertificate_Id?    Id                           { get; }

        /// <summary>
        /// Which trust domain this certificate anchors.
        /// </summary>
        [Mandatory]
        public RootCertificateType    RootType                     { get; }

        /// <summary>
        /// The certificate itself.
        /// </summary>
        [Mandatory]
        public PnCCertificate         Certificate                  { get; }

        /// <summary>
        /// The ISO 15118 generation this root belongs to.
        /// </summary>
        [Optional]
        public XSD_MsgDefNamespace?   XSDMsgDefNamespace           { get; }

        /// <summary>
        /// The certificate revocation list of this root, if the operator was given one.
        /// The specification gives no format for it.
        /// </summary>
        [Optional]
        public String?                CertificateRevocationList    { get; }

        /// <summary>
        /// A cross-certificate pair, if the operator was given one.
        /// </summary>
        [Optional]
        public String?                CrossCertificatePair         { get; }

        /// <summary>
        /// A URI describing this root (RFC 2079).
        /// </summary>
        [Optional]
        public URL?                   LabeledURI                   { get; }


        #region Derived from the certificate

        /// <summary>The distinguished name of the subject.</summary>
        public String                 DistinguishedName
            => Certificate.SubjectName;

        /// <summary>The common name of the subject.</summary>
        public String                 CommonName
            => Certificate.CommonName;

        /// <summary>The organization named in the subject.</summary>
        public String?                OrganizationName
            => Certificate.Organization;

        /// <summary>The serial number, as lowercase hexadecimal without separators.</summary>
        public String                 RootIssuerSerialNumber
            => Certificate.SerialNumber;

        /// <summary>The authority key identifier, base64-encoded.</summary>
        public String?                RootAuthorityKeyIdentifier
            => Certificate.AuthorityKeyIdentifier is not null
                   ? Convert.ToBase64String(Certificate.AuthorityKeyIdentifier)
                   : null;

        /// <summary>The authority key identifier, as lowercase hexadecimal.</summary>
        public String?                RootAuthorityKeyIdentifierHex
            => PnCCertificate.ToHex(Certificate.AuthorityKeyIdentifier);

        /// <summary>The beginning of the validity period.</summary>
        public DateTimeOffset         ValidFrom
            => Certificate.NotBefore;

        /// <summary>The end of the validity period.</summary>
        public DateTimeOffset         ValidTo
            => Certificate.NotAfter;

        /// <summary>The SHA-256 fingerprint.</summary>
        public String                 Fingerprint
            => Certificate.SHA256Fingerprint;

        /// <summary>The SHA-1 fingerprint.</summary>
        public String                 FingerprintSha1
            => Certificate.SHA1Fingerprint;

        /// <summary>The curve of this root's key.</summary>
        public SignatureAlgorithm?    SignatureAlgorithm
            => Certificate.SignatureAlgorithm;

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new root certificate pool entry.
        /// </summary>
        /// <param name="RootType">Which trust domain this certificate anchors.</param>
        /// <param name="Certificate">The certificate itself.</param>
        /// <param name="Id">An optional identification assigned by the pool.</param>
        /// <param name="XSDMsgDefNamespace">An optional ISO 15118 generation.</param>
        /// <param name="CertificateRevocationList">An optional certificate revocation list.</param>
        /// <param name="CrossCertificatePair">An optional cross-certificate pair.</param>
        /// <param name="LabeledURI">An optional describing URI.</param>
        public RootCertificate(RootCertificateType   RootType,
                               PnCCertificate        Certificate,
                               RootCertificate_Id?   Id                          = null,
                               XSD_MsgDefNamespace?  XSDMsgDefNamespace          = null,
                               String?               CertificateRevocationList   = null,
                               String?               CrossCertificatePair        = null,
                               URL?                  LabeledURI                  = null)
        {

            this.RootType                   = RootType;
            this.Certificate                = Certificate ?? throw new ArgumentNullException(nameof(Certificate));
            this.Id                         = Id;
            this.XSDMsgDefNamespace         = XSDMsgDefNamespace;
            this.CertificateRevocationList  = CertificateRevocationList;
            this.CrossCertificatePair       = CrossCertificatePair;
            this.LabeledURI                 = LabeledURI;

        }

        #endregion


        #region WithId(Id)

        /// <summary>
        /// Return this entry as the pool stored it, under the given identification.
        /// </summary>
        /// <param name="Id">The identification assigned by the pool.</param>
        public RootCertificate WithId(RootCertificate_Id Id)

            => new (RootType,
                    Certificate,
                    Id,
                    XSDMsgDefNamespace,
                    CertificateRevocationList,
                    CrossCertificatePair,
                    LabeledURI);

        #endregion

        #region (static) Parse   (JSON, CustomRootCertificateParser = null)

        /// <summary>
        /// Parse the given JSON representation of a root certificate.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="CustomRootCertificateParser">An optional delegate to parse custom root certificates.</param>
        public static RootCertificate Parse(JObject                                        JSON,
                                            CustomJObjectParserDelegate<RootCertificate>?  CustomRootCertificateParser   = null)
        {

            if (TryParse(JSON, out var rootCertificate, out var errorResponse, CustomRootCertificateParser))
                return rootCertificate;

            throw new ArgumentException($"The given JSON representation of a root certificate is invalid: {errorResponse}",
                                        nameof(JSON));

        }

        #endregion

        #region (static) TryParse(JSON, out RootCertificate, out ErrorResponse, CustomRootCertificateParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of a root certificate.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="RootCertificate">The parsed root certificate.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomRootCertificateParser">An optional delegate to parse custom root certificates.</param>
        public static Boolean TryParse(JObject                                        JSON,
                                       [NotNullWhen(true)]  out RootCertificate?      RootCertificate,
                                       [NotNullWhen(false)] out String?               ErrorResponse,
                                       CustomJObjectParserDelegate<RootCertificate>?  CustomRootCertificateParser   = null)
        {

            try
            {

                RootCertificate = null;

                #region RootType                     [mandatory]

                if (!JSON.ParseMandatory("rootType",
                                         "root certificate type",
                                         RootCertificateType.TryParse,
                                         out RootCertificateType RootType,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region Certificate                  [mandatory]

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

                #region Id                           [optional]

                if (JSON.ParseOptional("rootCertificateId",
                                       "root certificate identification",
                                       RootCertificate_Id.TryParse,
                                       out RootCertificate_Id? Id,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region XSDMsgDefNamespace           [optional]

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

                #region LabeledURI                   [optional]

                if (JSON.ParseOptional("labeledUri",
                                       "labeled URI",
                                       URL.TryParse,
                                       out URL? LabeledURI,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion


                RootCertificate = new RootCertificate(
                                      RootType,
                                      certificate,
                                      Id,
                                      XSDMsgDefNamespace,
                                      JSON.Value<String>("certificateRevocationList"),
                                      JSON.Value<String>("crossCertificatePair"),
                                      LabeledURI
                                  );

                if (CustomRootCertificateParser is not null)
                    RootCertificate = CustomRootCertificateParser(JSON, RootCertificate);

                return true;

            }
            catch (Exception e)
            {
                RootCertificate  = null;
                ErrorResponse    = "The given JSON representation of a root certificate is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomRootCertificateSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomRootCertificateSerializer">A delegate to serialize custom root certificates.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<RootCertificate>? CustomRootCertificateSerializer = null)
        {

            var json = JSONObject.Create(

                                 Id.HasValue
                                     ? new JProperty("rootCertificateId",              Id.Value.ToString())
                                     : null,

                                 new JProperty("rootType",                             RootType.   ToString()),
                                 new JProperty("caCertificate",                        Certificate.Base64),

                                 new JProperty("distinguishedName",                    DistinguishedName),
                                 new JProperty("commonName",                           CommonName),

                                 OrganizationName.IsNotNullOrEmpty()
                                     ? new JProperty("organizationName",               OrganizationName)
                                     : null,

                                 RootAuthorityKeyIdentifier    is not null
                                     ? new JProperty("rootAuthorityKeyIdentifier",     RootAuthorityKeyIdentifier)
                                     : null,

                                 RootAuthorityKeyIdentifierHex is not null
                                     ? new JProperty("rootAuthorityKeyIdentifierHex",  RootAuthorityKeyIdentifierHex)
                                     : null,

                                 new JProperty("rootIssuerSerialNumber",               RootIssuerSerialNumber),
                                 // Without fractional seconds, as the specification's own
                                 // examples write them: "2019-01-10T12:54:26Z".
                                 new JProperty("validFrom",                            ValidFrom.ToISO8601(false)),
                                 new JProperty("validTo",                              ValidTo.  ToISO8601(false)),
                                 new JProperty("fingerprint",                          Fingerprint),
                                 new JProperty("fingerprintSha1",                      FingerprintSha1),

                                 SignatureAlgorithm.HasValue
                                     ? new JProperty("signatureAlgorithm",             SignatureAlgorithm.Value.ToString())
                                     : null,

                                 XSDMsgDefNamespace.HasValue
                                     ? new JProperty("xsdMsgDefNamespace",             XSDMsgDefNamespace.Value.ToString())
                                     : null,

                                 CertificateRevocationList.IsNotNullOrEmpty()
                                     ? new JProperty("certificateRevocationList",      CertificateRevocationList)
                                     : null,

                                 CrossCertificatePair.IsNotNullOrEmpty()
                                     ? new JProperty("crossCertificatePair",           CrossCertificatePair)
                                     : null,

                                 LabeledURI.HasValue
                                     ? new JProperty("labeledUri",                     LabeledURI.Value.ToString())
                                     : null

                       );

            return CustomRootCertificateSerializer is not null
                       ? CustomRootCertificateSerializer(this, json)
                       : json;

        }

        #endregion


        #region Operator overloading

        #region Operator == (RootCertificate1, RootCertificate2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificate1">A root certificate.</param>
        /// <param name="RootCertificate2">Another root certificate.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (RootCertificate? RootCertificate1,
                                           RootCertificate? RootCertificate2)
        {

            if (ReferenceEquals(RootCertificate1, RootCertificate2))
                return true;

            if (RootCertificate1 is null || RootCertificate2 is null)
                return false;

            return RootCertificate1.Equals(RootCertificate2);

        }

        #endregion

        #region Operator != (RootCertificate1, RootCertificate2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificate1">A root certificate.</param>
        /// <param name="RootCertificate2">Another root certificate.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (RootCertificate? RootCertificate1,
                                           RootCertificate? RootCertificate2)

            => !(RootCertificate1 == RootCertificate2);

        #endregion

        #endregion

        #region IEquatable<RootCertificate> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two root certificates for equality.
        /// </summary>
        /// <param name="Object">A root certificate to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is RootCertificate rootCertificate &&
                   Equals(rootCertificate);

        #endregion

        #region Equals(RootCertificate)

        /// <summary>
        /// Compares two root certificates for equality.
        /// </summary>
        /// <param name="RootCertificate">A root certificate to compare with.</param>
        public Boolean Equals(RootCertificate? RootCertificate)

            => RootCertificate is not null &&

               Certificate.Equals(RootCertificate.Certificate) &&
               RootType.   Equals(RootCertificate.RootType)    &&

               Nullable.Equals(Id,                  RootCertificate.Id)                 &&
               Nullable.Equals(XSDMsgDefNamespace,  RootCertificate.XSDMsgDefNamespace) &&
               Nullable.Equals(LabeledURI,          RootCertificate.LabeledURI)         &&

               String.Equals(CertificateRevocationList,  RootCertificate.CertificateRevocationList,  StringComparison.Ordinal) &&
               String.Equals(CrossCertificatePair,       RootCertificate.CrossCertificatePair,       StringComparison.Ordinal);

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()
        {
            unchecked
            {
                return (Certificate.GetHashCode() * 5) ^
                       (RootType.   GetHashCode() * 3) ^
                       (Id?.        GetHashCode() ?? 0);
            }
        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{RootType} root '{CommonName}' ({Fingerprint[..16]}...), valid until {ValidTo:yyyy-MM-dd}";

        #endregion

    }

}
