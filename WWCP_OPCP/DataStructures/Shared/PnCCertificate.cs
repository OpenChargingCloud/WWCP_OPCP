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
using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using BCX509                    = Org.BouncyCastle.X509.X509Certificate;
using BCSubjectKeyIdentifier    = Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier;
using BCAuthorityKeyIdentifier  = Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier;

// The property below is named for the specification's field; the alias keeps the
// vocabulary type reachable from inside this class all the same.
using OPCPSignatureAlgorithm    = cloud.charging.open.protocols.opcp.SignatureAlgorithm;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// An X.509 certificate as OPCP carries it: bare base64-encoded DER, with no PEM armour
    /// anywhere in the protocol.
    ///
    /// The wrapper keeps the encoding it arrived in and answers the questions the pools ask about
    /// a certificate - who it names, when it is valid, which key identifies it, what it fingerprints
    /// to - without each service having to decode it again.
    /// </summary>
    /// <remarks>
    /// Parsing goes through BouncyCastle rather than <c>X509Certificate2</c> deliberately. OPCP
    /// admits Ed448 certificates, and whether a platform certificate store will load one is a
    /// platform question this library should not be asking. <see cref="ToDotNet"/> is there for
    /// the places that genuinely need the framework type, such as TLS.
    ///
    /// The 800-character limit the specification puts on several of these fields is a constraint of
    /// those fields, not of certificates, and is checked where the specification states it rather
    /// than here.
    /// </remarks>
    public class PnCCertificate : IEquatable<PnCCertificate>,
                                  IComparable<PnCCertificate>,
                                  IComparable
    {

        #region Data

        private readonly BCX509 certificate;

        #endregion

        #region Properties

        /// <summary>
        /// The certificate as it appears on the wire: base64-encoded DER, exactly as given.
        /// </summary>
        public String          Base64                    { get; }

        /// <summary>
        /// The DER encoding of the certificate.
        /// </summary>
        public Byte[]          DER
            => certificate.GetEncoded();

        /// <summary>
        /// The distinguished name of the subject, e.g. "CN=V2G Root CA G2, DC=V2G, O=Hubject GmbH, C=DE".
        /// </summary>
        public String          SubjectName               { get; }

        /// <summary>
        /// The common name of the subject. Across the Plug&amp;Charge ecosystem this is the
        /// identifier itself: a PCID on a provisioning certificate, an EMAID on a contract
        /// certificate, an EVSEID or SECCID on a charging station certificate.
        /// </summary>
        public String          CommonName                { get; }

        /// <summary>
        /// The organization named in the subject, when there is one. The root certificate
        /// pool publishes this beside the certificate as 'organizationName'.
        /// </summary>
        public String?         Organization              { get; }

        /// <summary>
        /// The distinguished name of the issuer.
        /// </summary>
        public String          IssuerName                { get; }

        /// <summary>
        /// The serial number, as lowercase hexadecimal without separators - the form the
        /// root certificate pool and the provisioning certificate pool both use.
        /// </summary>
        public String          SerialNumber              { get; }

        /// <summary>
        /// The beginning of the validity period.
        /// </summary>
        public DateTimeOffset  NotBefore                 { get; }

        /// <summary>
        /// The end of the validity period.
        /// </summary>
        public DateTimeOffset  NotAfter                  { get; }

        /// <summary>
        /// The subject key identifier, when the certificate carries one. ISO 15118 truncates
        /// these to eight bytes, which is why the ecosystem's examples are so short.
        /// </summary>
        public Byte[]?         SubjectKeyIdentifier      { get; }

        /// <summary>
        /// The key identifier of the issuing certificate, when the certificate carries one.
        /// </summary>
        public Byte[]?         AuthorityKeyIdentifier    { get; }

        /// <summary>
        /// Whether this certificate may issue other certificates.
        /// </summary>
        public Boolean         IsCertificateAuthority    { get; }

        /// <summary>
        /// The name of the algorithm this certificate was signed with,
        /// e.g. "SHA-256withECDSA".
        /// </summary>
        public String          SignatureAlgorithmName
            => certificate.SigAlgName;

        /// <summary>
        /// The curve of this certificate's key, in the vocabulary OPCP names its three
        /// signature algorithms by - or null for a key of some other kind.
        /// </summary>
        public OPCPSignatureAlgorithm?  SignatureAlgorithm    { get; }

        /// <summary>
        /// The SHA-256 fingerprint of the DER encoding, as lowercase hexadecimal without
        /// separators. This is the 'fingerprint' of the root certificate pool and the
        /// 'cpsV2GRootCertificateFingerprint' that identifies a signer.
        /// </summary>
        public String          SHA256Fingerprint         { get; }

        /// <summary>
        /// The SHA-1 fingerprint of the DER encoding, as lowercase hexadecimal without separators.
        /// </summary>
        public String          SHA1Fingerprint           { get; }

        /// <summary>
        /// The underlying BouncyCastle certificate, for the PKI operations that need it.
        /// </summary>
        public BCX509          BouncyCastleCertificate
            => certificate;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Plug&amp;Charge certificate from an already parsed certificate.
        /// </summary>
        /// <param name="Base64">The base64-encoded DER, as it arrived.</param>
        /// <param name="Certificate">The parsed certificate.</param>
        private PnCCertificate(String  Base64,
                               BCX509  Certificate)
        {

            var der = Certificate.GetEncoded();

            this.Base64                  = Base64;
            this.certificate             = Certificate;

            this.SubjectName             = ToDistinguishedName(Certificate.SubjectDN);
            this.IssuerName              = ToDistinguishedName(Certificate.IssuerDN);
            this.Organization            = GetAttribute(Certificate.SubjectDN, X509Name.O);
            this.SignatureAlgorithm      = ParseSignatureAlgorithm(Certificate);
            this.CommonName              = PKIFactory.GetCommonName(Certificate.SubjectDN);
            this.SerialNumber            = Certificate.SerialNumber.ToString(16).ToLowerInvariant();
            this.NotBefore               = new DateTimeOffset(Certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
            this.NotAfter                = new DateTimeOffset(Certificate.NotAfter. ToUniversalTime(), TimeSpan.Zero);

            this.SubjectKeyIdentifier    = ParseKeyIdentifier(Certificate, X509Extensions.SubjectKeyIdentifier);
            this.AuthorityKeyIdentifier  = ParseKeyIdentifier(Certificate, X509Extensions.AuthorityKeyIdentifier);

            // BouncyCastle reports -1 for a certificate that is not a CA, and the path length
            // constraint - or int.MaxValue when unconstrained - for one that is.
            this.IsCertificateAuthority  = Certificate.GetBasicConstraints() >= 0;

            this.SHA256Fingerprint       = Convert.ToHexString(SHA256.HashData(der)).ToLowerInvariant();
            this.SHA1Fingerprint         = Convert.ToHexString(SHA1.  HashData(der)).ToLowerInvariant();

        }

        #endregion


        #region (static) Parse    (Base64)

        /// <summary>
        /// Parse the given base64-encoded DER as a Plug&amp;Charge certificate.
        /// </summary>
        /// <param name="Base64">The base64-encoded DER of an X.509 certificate.</param>
        public static PnCCertificate Parse(String Base64)
        {

            if (TryParse(Base64, out var certificate, out var errorResponse))
                return certificate;

            throw new ArgumentException($"Invalid certificate: {errorResponse}",
                                        nameof(Base64));

        }

        #endregion

        #region (static) TryParse (Base64)

        /// <summary>
        /// Try to parse the given base64-encoded DER as a Plug&amp;Charge certificate.
        /// </summary>
        /// <param name="Base64">The base64-encoded DER of an X.509 certificate.</param>
        public static PnCCertificate? TryParse(String Base64)
        {

            if (TryParse(Base64, out var certificate, out _))
                return certificate;

            return null;

        }

        #endregion

        #region (static) TryParse (Base64, out Certificate, out ErrorResponse)

        /// <summary>
        /// Try to parse the given base64-encoded DER as a Plug&amp;Charge certificate.
        /// </summary>
        /// <param name="Base64">The base64-encoded DER of an X.509 certificate.</param>
        /// <param name="Certificate">The parsed certificate.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(String                                Base64,
                                       [NotNullWhen(true)]  out PnCCertificate?  Certificate,
                                       [NotNullWhen(false)] out String?          ErrorResponse)
        {

            Certificate    = null;
            ErrorResponse  = null;

            var text = Base64?.Trim() ?? "";

            if (text.IsNullOrEmpty())
            {
                ErrorResponse = "The given certificate must not be null or empty!";
                return false;
            }

            Byte[] der;

            try
            {
                der = Convert.FromBase64String(text);
            }
            catch (Exception e)
            {
                ErrorResponse = "The given certificate is not valid base64: " + e.Message;
                return false;
            }

            try
            {

                var parsed = new X509CertificateParser().ReadCertificate(der);

                if (parsed is null)
                {
                    ErrorResponse = "The given certificate could not be read as an X.509 certificate!";
                    return false;
                }

                Certificate = new PnCCertificate(text, parsed);
                return true;

            }
            catch (Exception e)
            {
                ErrorResponse = "The given certificate could not be read as an X.509 certificate: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (static) FromDER  (DER)

        /// <summary>
        /// Create a Plug&amp;Charge certificate from a DER encoding.
        /// </summary>
        /// <param name="DER">The DER encoding of an X.509 certificate.</param>
        public static PnCCertificate FromDER(Byte[] DER)

            => Parse(Convert.ToBase64String(DER));

        #endregion

        #region (static) From     (Certificate)

        /// <summary>
        /// Create a Plug&amp;Charge certificate from an already parsed BouncyCastle certificate.
        /// </summary>
        /// <param name="Certificate">A BouncyCastle X.509 certificate.</param>
        public static PnCCertificate From(BCX509 Certificate)

            => new (Convert.ToBase64String(Certificate.GetEncoded()),
                    Certificate);

        #endregion


        #region IsValidAt      (Timestamp)

        /// <summary>
        /// Whether this certificate is within its validity period at the given moment.
        /// </summary>
        /// <param name="Timestamp">A moment in time.</param>
        public Boolean IsValidAt(DateTimeOffset Timestamp)

            => Timestamp >= NotBefore &&
               Timestamp <= NotAfter;

        #endregion

        #region ToHex          (Bytes, Separator = null)

        /// <summary>
        /// Render the given bytes as lowercase hexadecimal.
        ///
        /// Key identifiers appear in OPCP in three encodings of the same bytes: base64 in the root
        /// certificate pool, colon-separated hexadecimal in the provisioning certificate pool, and
        /// plain hexadecimal beside them both.
        /// </summary>
        /// <param name="Bytes">The bytes to render.</param>
        /// <param name="Separator">An optional separator between the octets, e.g. ":".</param>
        /// <param name="Uppercase">Whether to render the digits uppercase.</param>
        public static String? ToHex(Byte[]?  Bytes,
                                    String?  Separator   = null,
                                    Boolean  Uppercase   = false)
        {

            if (Bytes is null)
                return null;

            var hex = Uppercase
                          ? Convert.ToHexString(Bytes)
                          : Convert.ToHexString(Bytes).ToLowerInvariant();

            if (Separator.IsNullOrEmpty())
                return hex;

            return String.Join(Separator,
                               Enumerable.Range(0, hex.Length / 2).
                                          Select(i => hex.Substring(i * 2, 2)));

        }

        #endregion

        #region ToPEM          ()

        /// <summary>
        /// Return the PEM encoding of this certificate. Nothing in OPCP transports PEM;
        /// this is for writing a certificate out to somewhere that expects it.
        /// </summary>
        public String ToPEM()

            => certificate.ToPEM();

        #endregion

        #region ToDotNet       ()

        /// <summary>
        /// Return this certificate as a framework certificate, for the places that need one.
        /// </summary>
        public System.Security.Cryptography.X509Certificates.X509Certificate2 ToDotNet()

            => System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(DER);

        #endregion


        #region (private, static) ToDistinguishedName(Name)

        /// <summary>
        /// Render an X.501 name the way a distinguished name is written: most specific component
        /// first, which is the reverse of the order it is encoded in.
        /// </summary>
        /// <remarks>
        /// BouncyCastle's own ToString() keeps the encoded order, so the reversing overload is what
        /// produces "CN=V2G Root CA G2,DC=V2G,O=Hubject GmbH,C=DE" rather than that name backwards.
        /// The specification writes its examples with a space after each comma; its pattern accepts
        /// either, and this form is taken from BouncyCastle unaltered because it escapes the
        /// component values correctly and hand-editing the separators would undo that.
        /// </remarks>
        private static String ToDistinguishedName(X509Name Name)

            => Name.ToString(true, X509Name.DefaultSymbols);

        #endregion

        #region (private, static) GetAttribute(Name, OID)

        /// <summary>
        /// Read one attribute out of an X.501 name, e.g. the organization.
        /// </summary>
        private static String? GetAttribute(X509Name             Name,
                                            DerObjectIdentifier  OID)
        {

            var oids    = Name.GetOidList();
            var values  = Name.GetValueList();

            for (var i = 0; i < oids.Count; i++)
                if (oids[i] is DerObjectIdentifier oid && oid.Equals(OID))
                    return values[i]?.ToString();

            return null;

        }

        #endregion

        #region (private, static) ParseSignatureAlgorithm(Certificate)

        /// <summary>
        /// Name the certificate's key by its curve, in the vocabulary OPCP uses.
        /// </summary>
        /// <remarks>
        /// OPCP calls these "signature algorithms" but names curves: secp256r1, secp521r1, ed448.
        /// The curve is read from the key's own algorithm parameters, and the SEC name is asked
        /// for first on purpose - BouncyCastle's general table answers "prime256v1" for the curve
        /// the specification calls secp256r1, and they are the same curve under two names.
        /// </remarks>
        private static OPCPSignatureAlgorithm? ParseSignatureAlgorithm(BCX509 Certificate)
        {

            try
            {

                var algorithm = Certificate.CertificateStructure.SubjectPublicKeyInfo.Algorithm;

                if (algorithm.Algorithm.Equals(EdECObjectIdentifiers.id_Ed448))
                    return OPCPSignatureAlgorithm.ed448;

                if (algorithm.Algorithm.Equals(EdECObjectIdentifiers.id_Ed25519))
                    return OPCPSignatureAlgorithm.Parse("ed25519");

                if (algorithm.Algorithm.Equals(X9ObjectIdentifiers.IdECPublicKey) &&
                    algorithm.Parameters is not null)
                {

                    var curve  = DerObjectIdentifier.GetInstance(algorithm.Parameters);

                    var name   = SecNamedCurves.    GetName(curve) ??
                                 ECNamedCurveTable. GetName(curve);

                    if (name.IsNotNullOrEmpty())
                        return OPCPSignatureAlgorithm.Parse(name);

                }

            }
            catch
            { }

            // An RSA or post-quantum key is not one of the three OPCP names, which is
            // information rather than an error.
            return null;

        }

        #endregion

        #region (private, static) ParseKeyIdentifier(Certificate, Extension)

        /// <summary>
        /// Read the key identifier out of a subject or authority key identifier extension.
        /// A certificate without the extension has no identifier, which is not an error.
        /// </summary>
        private static Byte[]? ParseKeyIdentifier(BCX509               Certificate,
                                                  DerObjectIdentifier  Extension)
        {

            try
            {

                var extensionValue = Certificate.GetExtensionValue(Extension);

                if (extensionValue is null)
                    return null;

                // An extension value is a DER octet string wrapping the extension's own encoding.
                var value = Asn1Object.FromByteArray(extensionValue.GetOctets());

                if (Extension.Equals(X509Extensions.SubjectKeyIdentifier))
                    return BCSubjectKeyIdentifier.  GetInstance(value).GetKeyIdentifier();

                // An authority key identifier may name the issuer by its certificate rather
                // than by a key identifier, in which case there is nothing to return.
                return BCAuthorityKeyIdentifier.GetInstance(value).KeyIdentifier?.GetOctets();

            }
            catch
            {
                // A malformed or absent key identifier must not make an otherwise
                // readable certificate unreadable.
                return null;
            }

        }

        #endregion


        #region Operator overloading

        #region Operator == (Certificate1, Certificate2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="Certificate1">A certificate.</param>
        /// <param name="Certificate2">Another certificate.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (PnCCertificate? Certificate1,
                                           PnCCertificate? Certificate2)
        {

            if (ReferenceEquals(Certificate1, Certificate2))
                return true;

            if (Certificate1 is null || Certificate2 is null)
                return false;

            return Certificate1.Equals(Certificate2);

        }

        #endregion

        #region Operator != (Certificate1, Certificate2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="Certificate1">A certificate.</param>
        /// <param name="Certificate2">Another certificate.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (PnCCertificate? Certificate1,
                                           PnCCertificate? Certificate2)

            => !(Certificate1 == Certificate2);

        #endregion

        #endregion

        #region IComparable<PnCCertificate> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two certificates.
        /// </summary>
        /// <param name="Object">A certificate to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is PnCCertificate certificate
                   ? CompareTo(certificate)
                   : throw new ArgumentException("The given object is not a certificate!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(Certificate)

        /// <summary>
        /// Compares two certificates by their SHA-256 fingerprint.
        /// </summary>
        /// <param name="Certificate">A certificate to compare with.</param>
        public Int32 CompareTo(PnCCertificate? Certificate)

            => Certificate is null
                   ? 1
                   : String.Compare(SHA256Fingerprint,
                                    Certificate.SHA256Fingerprint,
                                    StringComparison.Ordinal);

        #endregion

        #endregion

        #region IEquatable<PnCCertificate> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two certificates for equality.
        /// </summary>
        /// <param name="Object">A certificate to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is PnCCertificate certificate &&
                   Equals(certificate);

        #endregion

        #region Equals(Certificate)

        /// <summary>
        /// Compares two certificates for equality.
        ///
        /// Two certificates are the same certificate when their DER encodings are, whatever
        /// whitespace or line breaks their base64 arrived with.
        /// </summary>
        /// <param name="Certificate">A certificate to compare with.</param>
        public Boolean Equals(PnCCertificate? Certificate)

            => Certificate is not null &&
               SHA256Fingerprint.Equals(Certificate.SHA256Fingerprint, StringComparison.Ordinal);

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => SHA256Fingerprint.GetHashCode();

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{CommonName} ({SHA256Fingerprint[..16]}...), valid until {NotAfter:yyyy-MM-dd}";

        #endregion

    }

}
