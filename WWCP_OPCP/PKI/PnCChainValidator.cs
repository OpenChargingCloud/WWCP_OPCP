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

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// What validating one certificate chain came to.
    /// </summary>
    /// <param name="IsValid">Whether the chain is acceptable.</param>
    /// <param name="Reason">Why not, when it is not. The first thing that was wrong, named.</param>
    /// <param name="Anchor">The root it chained to, when it did.</param>
    public sealed record ChainValidationResult(Boolean         IsValid,
                                               String          Reason,
                                               PnCCertificate? Anchor)
    {

        /// <summary>
        /// The chain is acceptable.
        /// </summary>
        /// <param name="Anchor">The root it chained to.</param>
        public static ChainValidationResult Valid(PnCCertificate Anchor)
            => new (true, "ok", Anchor);

        /// <summary>
        /// The chain is not acceptable.
        /// </summary>
        /// <param name="Reason">Why not.</param>
        public static ChainValidationResult Invalid(String Reason)
            => new (false, Reason, null);

    }


    /// <summary>
    /// Validates an ISO 15118 certificate chain.
    ///
    /// This is the check the provisioning certificate pool makes before it stores a vehicle's
    /// certificate and again before it hands it out, and the one a mobility operator makes before
    /// concluding a contract: the leaf, its sub-CAs, and a root the recipient already trusts.
    /// </summary>
    /// <remarks>
    /// Validation goes through BouncyCastle rather than the platform's chain engine. The chain
    /// engine would be less code, but it cannot be asked about an Ed448 chain on every platform,
    /// and it wants certificates in a store rather than in a request body. Doing it here also
    /// makes the shell model explicit, which is what the specification asks for: every certificate
    /// on the path has to be valid at the moment of the check, not merely to have been valid when
    /// the one below it was issued.
    /// </remarks>
    public static class PnCChainValidator
    {

        #region Validate(Leaf, SubCAs, TrustedRoots, Timestamp = null, ExpectedCommonName = null, RevocationChecker = null)

        /// <summary>
        /// Validate a certificate chain.
        /// </summary>
        /// <param name="Leaf">The end entity certificate.</param>
        /// <param name="SubCAs">The intermediate certificates, in any order.</param>
        /// <param name="TrustedRoots">The roots the caller is willing to believe.</param>
        /// <param name="Timestamp">The moment to validate at, or now.</param>
        /// <param name="ExpectedCommonName">
        /// The identifier the leaf is supposed to name - a PCID, an EMAID, an EVSEID. In ISO 15118
        /// the common name is the identifier, so a certificate naming something else is a
        /// certificate for something else.
        /// </param>
        /// <param name="RevocationChecker">An optional check of whether a certificate has been revoked.</param>
        public static ChainValidationResult Validate(PnCCertificate                 Leaf,
                                                     IEnumerable<PnCCertificate>    SubCAs,
                                                     IEnumerable<PnCCertificate>    TrustedRoots,
                                                     DateTimeOffset?                Timestamp            = null,
                                                     String?                        ExpectedCommonName   = null,
                                                     Func<PnCCertificate, Boolean>? RevocationChecker    = null)
        {

            var timestamp  = Timestamp ?? DateTimeOffset.UtcNow;
            var roots      = TrustedRoots.ToArray();
            var subCAs     = SubCAs.      ToArray();

            if (roots.Length == 0)
                return ChainValidationResult.Invalid("No trusted roots are configured, so nothing can be validated!");

            #region The leaf has to name what was asked for

            if (ExpectedCommonName is not null &&
               !String.Equals(Leaf.CommonName, ExpectedCommonName, StringComparison.OrdinalIgnoreCase))
            {
                return ChainValidationResult.Invalid(
                           $"The certificate names '{Leaf.CommonName}', not '{ExpectedCommonName}'!"
                       );
            }

            #endregion

            #region Walk from the leaf to a trusted root

            var path     = new List<PnCCertificate> { Leaf };
            var current  = Leaf;
            var unused   = subCAs.ToList();

            while (true)
            {

                #region Did we arrive at something the caller trusts?

                var anchor = roots.FirstOrDefault(root => IsIssuedBy(current, root));

                if (anchor is not null)
                {

                    path.Add(anchor);

                    foreach (var certificate in path)
                    {

                        // The shell model: every certificate on the path has to be valid now,
                        // not merely to have been valid when the one below it was issued.
                        if (!certificate.IsValidAt(timestamp))
                            return ChainValidationResult.Invalid(
                                       $"'{certificate.CommonName}' is not valid at {timestamp:yyyy-MM-dd HH:mm:ss} UTC " +
                                       $"({certificate.NotBefore:yyyy-MM-dd} to {certificate.NotAfter:yyyy-MM-dd})!"
                                   );

                        if (RevocationChecker is not null && RevocationChecker(certificate))
                            return ChainValidationResult.Invalid($"'{certificate.CommonName}' has been revoked!");

                    }

                    return ChainValidationResult.Valid(anchor);

                }

                #endregion

                #region Otherwise climb one certificate

                var issuer = unused.FirstOrDefault(subCA => IsIssuedBy(current, subCA));

                if (issuer is null)
                    return ChainValidationResult.Invalid(
                               $"'{current.CommonName}' was issued by '{current.IssuerName}', " +
                                "which is neither a trusted root nor among the given intermediate certificates!"
                           );

                if (!issuer.IsCertificateAuthority)
                    return ChainValidationResult.Invalid(
                               $"'{issuer.CommonName}' issued '{current.CommonName}' but is not a certification authority!"
                           );

                unused.Remove(issuer);
                path.  Add   (issuer);

                current = issuer;

                #endregion

            }

            #endregion

        }

        #endregion

        #region Validate(Leaf, SubCAs, TrustedRoots, ...)   [PCID / EMAID overloads]

        /// <summary>
        /// Validate the certificate a vehicle was born with. Its common name has to be the PCID.
        /// </summary>
        /// <param name="Leaf">The provisioning certificate.</param>
        /// <param name="SubCAs">The intermediate certificates.</param>
        /// <param name="TrustedRoots">The manufacturers' roots.</param>
        /// <param name="PCID">The vehicle the certificate is supposed to be for.</param>
        /// <param name="Timestamp">The moment to validate at, or now.</param>
        /// <param name="RevocationChecker">An optional check of whether a certificate has been revoked.</param>
        public static ChainValidationResult ValidateProvisioningCertificate(PnCCertificate                 Leaf,
                                                                            IEnumerable<PnCCertificate>    SubCAs,
                                                                            IEnumerable<PnCCertificate>    TrustedRoots,
                                                                            PCID                           PCID,
                                                                            DateTimeOffset?                Timestamp           = null,
                                                                            Func<PnCCertificate, Boolean>? RevocationChecker   = null)

            => Validate(Leaf, SubCAs, TrustedRoots, Timestamp, PCID.ToString(), RevocationChecker);

        /// <summary>
        /// Validate a contract certificate. Its common name has to be the EMAID.
        /// </summary>
        /// <param name="Leaf">The contract certificate.</param>
        /// <param name="SubCAs">The intermediate certificates.</param>
        /// <param name="TrustedRoots">The roots to validate against.</param>
        /// <param name="EMAId">The contract the certificate is supposed to be for.</param>
        /// <param name="Timestamp">The moment to validate at, or now.</param>
        /// <param name="RevocationChecker">An optional check of whether a certificate has been revoked.</param>
        public static ChainValidationResult ValidateContractCertificate(PnCCertificate                 Leaf,
                                                                        IEnumerable<PnCCertificate>    SubCAs,
                                                                        IEnumerable<PnCCertificate>    TrustedRoots,
                                                                        EMA_Id                         EMAId,
                                                                        DateTimeOffset?                Timestamp           = null,
                                                                        Func<PnCCertificate, Boolean>? RevocationChecker   = null)

            => Validate(Leaf, SubCAs, TrustedRoots, Timestamp, EMAId.ToString(), RevocationChecker);

        #endregion

        #region (private, static) IsIssuedBy(Certificate, Issuer)

        /// <summary>
        /// Whether the given certificate was issued by the given one.
        ///
        /// Names are compared first because verifying a signature is far more expensive, but the
        /// signature is what decides: a matching issuer name proves nothing on its own, and anyone
        /// can put any name in a certificate they generate.
        /// </summary>
        private static Boolean IsIssuedBy(PnCCertificate  Certificate,
                                          PnCCertificate  Issuer)
        {

            if (!String.Equals(Certificate.IssuerName, Issuer.SubjectName, StringComparison.Ordinal))
                return false;

            try
            {
                Certificate.BouncyCastleCertificate.Verify(Issuer.BouncyCastleCertificate.GetPublicKey());
                return true;
            }
            catch
            {
                return false;
            }

        }

        #endregion

    }

}
