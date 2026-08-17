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
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

using org.GraphDefined.Vanaheimr.Illias;

using BCX509 = Org.BouncyCastle.X509;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A PKCS#7 structure carrying certificates and nothing else - the envelope RFC 7030 answers
    /// enrollment and CA distribution with.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It is a CMS <c>SignedData</c> with no signers, no content and no revocation lists: a
    /// degenerate signature whose entire purpose is to be a list of certificates that survives
    /// being sent over something that expects one blob. RFC 5652 §5.2 spells out this exact use,
    /// and RFC 7030 §4.1.3 names it <c>application/pkcs7-mime; smime-type=certs-only</c>.
    /// </para>
    /// <para>
    /// Written here against BouncyCastle's ASN.1 layer rather than its CMS generator, because a
    /// generator that expects to sign something has to be talked out of it, and the structure is
    /// four fields long.
    /// </para>
    /// <para>
    /// <b>The format does not keep the order.</b> The certificates live in an ASN.1 SET OF, and
    /// DER requires the members of a set to be sorted by their own encoding - so the leaf-first
    /// order an enrollment answer is written in is gone by the time it is read. Rather than fight
    /// that with a looser encoding, the reader puts the chain back together the way a verifier
    /// would anyway: the certificate nothing else in the set was issued by is the leaf, and each
    /// one after it is the one that issued the one before.
    /// </para>
    /// </remarks>
    public static class Pkcs7CertificateContainer
    {

        #region Create   (Certificates)

        /// <summary>
        /// Wrap certificates in a certificates-only PKCS#7 structure.
        /// </summary>
        /// <param name="Certificates">The certificates, leaf first.</param>
        public static Byte[] Create(params PnCCertificate[] Certificates)

            => Create((IEnumerable<PnCCertificate>) Certificates);


        /// <summary>
        /// Wrap certificates in a certificates-only PKCS#7 structure.
        /// </summary>
        /// <param name="Certificates">The certificates, leaf first.</param>
        public static Byte[] Create(IEnumerable<PnCCertificate> Certificates)
        {

            var certificates = Certificates.ToArray();

            if (certificates.Length == 0)
                throw new ArgumentException("A certificates-only PKCS#7 structure without certificates would say nothing!",
                                            nameof(Certificates));

            var signedData = new SignedData(

                                 // No digest algorithms, because nothing was digested.
                                 new DerSet(Array.Empty<Asn1Encodable>()),

                                 // An id-data content info with no content: the structure exists
                                 // for what it carries beside the content, not for the content.
                                 new ContentInfo(CmsObjectIdentifiers.Data, null),

                                 new DerSet(
                                     certificates.Select(certificate =>
                                         (Asn1Encodable) X509CertificateStructure.GetInstance(
                                             Asn1Object.FromByteArray(certificate.DER)
                                         )).ToArray()
                                 ),

                                 // No revocation lists, and no signers - which is what makes this
                                 // "certs-only" rather than a signature.
                                 null,
                                 new DerSet(Array.Empty<Asn1Encodable>())

                             );

            return new ContentInfo(
                       CmsObjectIdentifiers.SignedData,
                       signedData
                   ).GetEncoded(Asn1Encodable.Der);

        }

        #endregion

        #region ToBase64 (Certificates)

        /// <summary>
        /// A certificates-only PKCS#7 structure, base64-encoded - which is how enrollment
        /// transports it.
        /// </summary>
        /// <param name="Certificates">The certificates, leaf first.</param>
        public static String ToBase64(IEnumerable<PnCCertificate> Certificates)

            => Convert.ToBase64String(Create(Certificates));

        #endregion


        #region TryParse (DER,    out Certificates, out ErrorResponse)

        /// <summary>
        /// Read the certificates out of a PKCS#7 structure.
        /// </summary>
        /// <param name="DER">The DER encoding of the structure.</param>
        /// <param name="Certificates">The certificates it carries, in the order it carries them.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        public static Boolean TryParse(Byte[]                                 DER,
                                       [NotNullWhen(true)]  out PnCCertificate[]?  Certificates,
                                       [NotNullWhen(false)] out String?       ErrorResponse)
        {

            Certificates   = null;
            ErrorResponse  = null;

            try
            {

                var contentInfo = ContentInfo.GetInstance(Asn1Object.FromByteArray(DER));

                if (!CmsObjectIdentifiers.SignedData.Equals(contentInfo.ContentType))
                {
                    ErrorResponse = $"The given PKCS#7 structure is not signed data, but '{contentInfo.ContentType}'!";
                    return false;
                }

                var signedData  = SignedData.GetInstance(contentInfo.Content);
                var certificates = signedData.Certificates;

                if (certificates is null || certificates.Count == 0)
                {
                    ErrorResponse = "The given PKCS#7 structure carries no certificates!";
                    return false;
                }

                var parsed = new List<PnCCertificate>();

                foreach (var certificate in certificates)
                    parsed.Add(
                        PnCCertificate.From(
                            new BCX509.X509Certificate(
                                X509CertificateStructure.GetInstance(certificate)
                            )
                        )
                    );

                Certificates = LeafFirst(parsed);
                return true;

            }
            catch (Exception e)
            {
                ErrorResponse = "The given PKCS#7 structure could not be read: " + e.Message;
                return false;
            }

        }

        #endregion

        #region TryParse (Base64, out Certificates, out ErrorResponse)

        /// <summary>
        /// Read the certificates out of a base64-encoded PKCS#7 structure.
        /// </summary>
        /// <param name="Base64">The base64-encoded structure, with or without PEM armour.</param>
        /// <param name="Certificates">The certificates it carries, in the order it carries them.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        public static Boolean TryParse(String                                      Base64,
                                       [NotNullWhen(true)]  out PnCCertificate[]?  Certificates,
                                       [NotNullWhen(false)] out String?            ErrorResponse)
        {

            Certificates   = null;
            ErrorResponse  = null;

            if (Base64.IsNullOrEmpty())
            {
                ErrorResponse = "The given PKCS#7 structure must not be null or empty!";
                return false;
            }

            try
            {
                return TryParse(Convert.FromBase64String(Unarmour(Base64)),
                                out Certificates,
                                out ErrorResponse);
            }
            catch (Exception e)
            {
                ErrorResponse = "The given PKCS#7 structure is not valid base64: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (static) LeafFirst(Certificates)

        /// <summary>
        /// Put a set of certificates back into chain order: the leaf first, then whatever issued
        /// it, up to the root if one is there.
        /// </summary>
        /// <param name="Certificates">Certificates, in whatever order they arrived in.</param>
        /// <remarks>
        /// The leaf is the one nothing else in the set was issued by. Anything the walk cannot
        /// reach - a second chain, a stray certificate - is appended rather than dropped: this
        /// orders what it was given and never decides that part of it should not exist.
        /// </remarks>
        public static PnCCertificate[] LeafFirst(IEnumerable<PnCCertificate> Certificates)
        {

            var certificates = Certificates.ToArray();

            if (certificates.Length < 2)
                return certificates;

            var leaf = certificates.FirstOrDefault(
                           candidate => !certificates.Any(other => other != candidate &&
                                                                   other.IssuerName == candidate.SubjectName)
                       );

            if (leaf is null)
                return certificates;

            var ordered  = new List<PnCCertificate> { leaf };
            var current  = leaf;

            while (true)
            {

                // A self-signed certificate issued itself, which is where every chain ends.
                if (current.SubjectName == current.IssuerName)
                    break;

                var issuer = certificates.FirstOrDefault(candidate => candidate.SubjectName == current.IssuerName &&
                                                                      !ordered.Contains(candidate));

                if (issuer is null)
                    break;

                ordered.Add(issuer);
                current = issuer;

            }

            ordered.AddRange(certificates.Where(certificate => !ordered.Contains(certificate)));

            return [.. ordered];

        }

        #endregion

        #region (private, static) Unarmour(Text)

        /// <summary>
        /// Strip PEM armour and line breaks, so that a structure written for a human file and one
        /// written for a wire both read.
        /// </summary>
        private static String Unarmour(String Text)

            => new (
                   [.. Text.Split('\n', '\r').
                            Where (line => !line.TrimStart().StartsWith("-----")).
                            SelectMany(line => line.Trim())]
               );

        #endregion

    }

}
