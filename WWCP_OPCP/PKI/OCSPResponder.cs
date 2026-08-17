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

using System.Collections.Concurrent;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Why a certificate was revoked (RFC 5280 §5.3.1).
    /// </summary>
    public enum RevocationReason
    {

        /// <summary>No reason was given.</summary>
        Unspecified          = 0,

        /// <summary>The private key was compromised.</summary>
        KeyCompromise        = 1,

        /// <summary>The issuing authority's key was compromised.</summary>
        CACompromise         = 2,

        /// <summary>The subject's affiliation changed.</summary>
        AffiliationChanged   = 3,

        /// <summary>The certificate was replaced.</summary>
        Superseded           = 4,

        /// <summary>The certificate is no longer needed.</summary>
        CessationOfOperation = 5,

        /// <summary>The certificate is on hold.</summary>
        CertificateHold      = 6

    }


    /// <summary>
    /// Answers whether the certificates one authority issued are still good.
    ///
    /// The Plug&amp;Charge ecosystem leans on this in more places than it looks: publishing a
    /// vehicle's certificate checks it, handing that certificate out checks it again, and a
    /// mobility operator checks it before concluding a contract. The specification requires the
    /// V2G PKI to operate responders and requires them to answer without authentication - a
    /// revocation check that needed a token would fail exactly when it mattered.
    /// </summary>
    public class OCSPResponder
    {

        #region Data

        private readonly ConcurrentDictionary<String, (DateTimeOffset RevokedAt, RevocationReason Reason)> revoked = new (StringComparer.Ordinal);

        #endregion

        #region Properties

        /// <summary>
        /// The authority whose certificates this responder answers for.
        /// </summary>
        public PnCCertificate           IssuerCertificate    { get; }

        /// <summary>
        /// The key this responder signs its answers with.
        /// </summary>
        public AsymmetricKeyParameter   SigningKey           { get; }

        /// <summary>
        /// The certificate the answers are signed under, which the asker validates against
        /// the issuer.
        /// </summary>
        public PnCCertificate           SignerCertificate    { get; }

        /// <summary>
        /// How many certificates are currently revoked.
        /// </summary>
        public Int32                    RevokedCount
            => revoked.Count;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a responder for the certificates of one authority.
        /// </summary>
        /// <param name="IssuerCertificate">The authority whose certificates this responder answers for.</param>
        /// <param name="SigningKey">The key to sign the answers with.</param>
        /// <param name="SignerCertificate">
        /// An optional certificate to sign under, otherwise the authority's own - which is what
        /// RFC 6960 calls a responder signing directly as the issuing CA.
        /// </param>
        public OCSPResponder(PnCCertificate          IssuerCertificate,
                             AsymmetricKeyParameter  SigningKey,
                             PnCCertificate?         SignerCertificate   = null)
        {

            this.IssuerCertificate  = IssuerCertificate ?? throw new ArgumentNullException(nameof(IssuerCertificate));
            this.SigningKey         = SigningKey        ?? throw new ArgumentNullException(nameof(SigningKey));
            this.SignerCertificate  = SignerCertificate ?? IssuerCertificate;

        }

        /// <summary>
        /// Create a responder for the certificates of one authority.
        /// </summary>
        /// <param name="Issuer">The authority whose certificates this responder answers for.</param>
        public OCSPResponder(IssuedCertificate Issuer)

            : this(Issuer.Certificate,
                   Issuer.PrivateKey)

        { }

        #endregion


        #region Revoke  (Certificate, Reason = null, RevokedAt = null)

        /// <summary>
        /// Record that a certificate is no longer good.
        /// </summary>
        /// <param name="Certificate">The certificate to revoke.</param>
        /// <param name="Reason">An optional reason.</param>
        /// <param name="RevokedAt">An optional moment of revocation, otherwise now.</param>
        public void Revoke(PnCCertificate     Certificate,
                           RevocationReason?  Reason      = null,
                           DateTimeOffset?    RevokedAt   = null)
        {

            revoked[Certificate.SerialNumber] = (
                RevokedAt ?? DateTimeOffset.UtcNow,
                Reason    ?? RevocationReason.Unspecified
            );

        }

        #endregion

        #region Unrevoke(Certificate)

        /// <summary>
        /// Forget that a certificate was revoked. For putting a test back to a known state -
        /// a real revocation is not undone.
        /// </summary>
        /// <param name="Certificate">The certificate.</param>
        public Boolean Unrevoke(PnCCertificate Certificate)

            => revoked.TryRemove(Certificate.SerialNumber, out _);

        #endregion

        #region IsRevoked(Certificate)

        /// <summary>
        /// Whether this responder considers the given certificate revoked.
        /// </summary>
        /// <param name="Certificate">A certificate.</param>
        public Boolean IsRevoked(PnCCertificate Certificate)

            => revoked.ContainsKey(Certificate.SerialNumber);

        #endregion


        #region Respond(RequestDER)

        /// <summary>
        /// Answer an OCSP request.
        /// </summary>
        /// <param name="RequestDER">The DER encoding of an OCSP request.</param>
        /// <returns>The DER encoding of an OCSP response - including for a request that made no sense,
        /// because RFC 6960 says a responder answers with a status rather than with nothing.</returns>
        public Byte[] Respond(Byte[] RequestDER)
        {

            var generator = new OCSPRespGenerator();

            try
            {

                var request       = new OcspReq(RequestDER);
                var requestList   = request.GetRequestList();

                if (requestList.Length == 0)
                    return generator.Generate(OCSPRespGenerator.MalformedRequest, null).GetEncoded();

                var responses     = new BasicOcspRespGenerator(
                                        SignerCertificate.BouncyCastleCertificate.GetPublicKey()
                                    );

                var thisUpdate    = DateTime.UtcNow;
                var nextUpdate    = thisUpdate.AddHours(1);

                foreach (var singleRequest in requestList)
                {

                    var certificateID = singleRequest.GetCertID();

                    responses.AddResponse(
                        certificateID,
                        StatusOf(certificateID),
                        thisUpdate,
                        nextUpdate,
                        null
                    );

                }

                var basicResponse = responses.Generate(
                                        SignatureAlgorithmNameOf(SigningKey),
                                        SigningKey,
                                        [ SignerCertificate.BouncyCastleCertificate ],
                                        thisUpdate
                                    );

                return generator.Generate(OCSPRespGenerator.Successful, basicResponse).GetEncoded();

            }
            catch
            {
                // A responder that threw would leave the asker unable to tell "revoked" from
                // "the responder is broken", and those call for very different reactions.
                return generator.Generate(OCSPRespGenerator.MalformedRequest, null).GetEncoded();
            }

        }

        #endregion

        #region (private) StatusOf(CertificateID)

        /// <summary>
        /// The status of one certificate.
        /// </summary>
        /// <remarks>
        /// A serial this responder has never heard of is answered "good", not "unknown". That is
        /// RFC 6960's own caveat about responders that do not know the full set of issued serials,
        /// and it is what this responder is: it knows what was revoked, not what exists.
        /// </remarks>
        private CertificateStatus? StatusOf(CertificateID CertificateID)
        {

            var serialNumber = CertificateID.SerialNumber.ToString(16).ToLowerInvariant();

            if (revoked.TryGetValue(serialNumber, out var revocation))
                return new RevokedStatus(
                           revocation.RevokedAt.UtcDateTime,
                           (Int32) revocation.Reason
                       );

            // BouncyCastle spells "good" as a null status.
            return CertificateStatus.Good;

        }

        #endregion

        #region (internal, static) SignatureAlgorithmNameOf(Key)

        /// <summary>
        /// The signature algorithm to use with the given key.
        /// </summary>
        internal static String SignatureAlgorithmNameOf(AsymmetricKeyParameter Key)

            => Key.GetType().Name.Contains("Ed448", StringComparison.OrdinalIgnoreCase)
                   ? "Ed448"
                   : "SHA256withECDSA";

        #endregion

        #region (internal, static) CertificateIDOf(Certificate, Issuer)

        /// <summary>
        /// Build the identification RFC 6960 asks a certificate by: not its serial alone, but the
        /// serial together with hashes of its issuer's name and key - so that two authorities
        /// using the same serial cannot be confused for one another.
        /// </summary>
        internal static CertificateID CertificateIDOf(PnCCertificate  Certificate,
                                                      PnCCertificate  Issuer)

            => new (
                   // SHA-1 is not a security choice here: RFC 6960 identifies a certificate by
                   // hashes of its issuer's name and key, and interoperable responders expect
                   // this one. Nothing is being authenticated by it.
                   new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance),
                   Issuer.BouncyCastleCertificate,
                   Certificate.BouncyCastleCertificate.SerialNumber
               );

        #endregion

    }

}
