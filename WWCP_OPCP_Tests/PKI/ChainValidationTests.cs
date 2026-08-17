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

namespace cloud.charging.open.protocols.opcp.Tests.PKI
{

    /// <summary>
    /// Validating an ISO 15118 certificate chain: the check the provisioning certificate pool
    /// makes before it stores a vehicle's certificate, and again before it hands it out.
    /// </summary>
    [TestFixture]
    public class ChainValidationTests
    {

        #region Data

        private PnCTestPKI  pki    = null!;
        private PCID        pcid;

        [OneTimeSetUp]
        public void BuildPKI()
        {
            pki   = new PnCTestPKI();
            pcid  = PCID.Parse("ECD12345671234567");
        }

        #endregion


        #region A_well_formed_chain_validates(Algorithm)

        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        [TestCase("ed448")]
        public void A_well_formed_chain_validates(String Algorithm)
        {

            var ownPKI   = new PnCTestPKI(SignatureAlgorithm.Parse(Algorithm));
            var vehicle  = ownPKI.IssueProvisioningCertificate(pcid);

            var result   = PnCChainValidator.ValidateProvisioningCertificate(
                               vehicle.Certificate,
                               vehicle.SubCAs,
                               [ ownPKI.OEMRoot.Certificate ],
                               pcid
                           );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.True, result.Reason);
                Assert.That(result.Anchor,   Is.EqualTo(ownPKI.OEMRoot.Certificate));
            });

        }

        #endregion

        #region The_order_of_the_sub_CAs_does_not_matter()

        /// <summary>
        /// The specification's own contract data lists the sub-CAs deepest-first while the
        /// provisioning certificate pool names them the other way round. Sorting that out is not
        /// the caller's job.
        /// </summary>
        [Test]
        public void The_order_of_the_sub_CAs_does_not_matter()
        {

            var vehicle = pki.IssueProvisioningCertificate(pcid);

            var forwards  = PnCChainValidator.Validate(vehicle.Certificate, vehicle.SubCAs,          [ pki.OEMRoot.Certificate ]);
            var backwards = PnCChainValidator.Validate(vehicle.Certificate, vehicle.SubCAs.Reverse(), [ pki.OEMRoot.Certificate ]);

            Assert.Multiple(() => {
                Assert.That(forwards.IsValid,   Is.True, forwards.Reason);
                Assert.That(backwards.IsValid,  Is.True, backwards.Reason);
            });

        }

        #endregion

        #region A_chain_to_an_untrusted_root_is_refused()

        /// <summary>
        /// Everything about this certificate is well-formed. It is refused for the one reason
        /// that matters: nobody here has any reason to believe its root.
        /// </summary>
        [Test]
        public void A_chain_to_an_untrusted_root_is_refused()
        {

            var stranger = pki.IssueUntrusted(pcid.ToString());

            var result   = PnCChainValidator.Validate(
                               stranger.Certificate,
                               stranger.SubCAs,
                               [ pki.OEMRoot.Certificate, pki.V2GRoot.Certificate, pki.MORoot.Certificate ]
                           );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("neither a trusted root"));
                Assert.That(result.Anchor,   Is.Null);
            });

        }

        #endregion

        #region A_certificate_naming_another_vehicle_is_refused()

        /// <summary>
        /// A perfectly valid certificate for a different vehicle is still the wrong certificate.
        /// </summary>
        [Test]
        public void A_certificate_naming_another_vehicle_is_refused()
        {

            var vehicle = pki.IssueProvisioningCertificate(PCID.Parse("ECD99999999999999"));

            var result  = PnCChainValidator.ValidateProvisioningCertificate(
                              vehicle.Certificate,
                              vehicle.SubCAs,
                              [ pki.OEMRoot.Certificate ],
                              pcid
                          );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("ECD99999999999999").And.Contains(pcid.ToString()));
            });

        }

        #endregion

        #region An_expired_certificate_is_refused()

        /// <summary>
        /// Validation happens at a moment, and the moment is a parameter - so expiry can be tested
        /// by looking from the future rather than by waiting for one.
        /// </summary>
        [Test]
        public void An_expired_certificate_is_refused()
        {

            var vehicle = pki.IssueProvisioningCertificate(pcid, TimeSpan.FromDays(30));

            var now     = PnCChainValidator.Validate(vehicle.Certificate, vehicle.SubCAs, [ pki.OEMRoot.Certificate ]);

            var later   = PnCChainValidator.Validate(vehicle.Certificate,
                                                     vehicle.SubCAs,
                                                     [ pki.OEMRoot.Certificate ],
                                                     vehicle.Certificate.NotAfter.AddDays(1));

            Assert.Multiple(() => {
                Assert.That(now.IsValid,      Is.True, now.Reason);
                Assert.That(later.IsValid,    Is.False);
                Assert.That(later.Reason,     Does.Contain("is not valid at"));
            });

        }

        #endregion

        #region The_shell_model_covers_the_whole_path()

        /// <summary>
        /// The specification asks for the shell model: every certificate on the path has to be
        /// valid at the moment of the check, not merely to have been valid when the one below it
        /// was issued.
        /// </summary>
        /// <remarks>
        /// The case where a leaf outlives its issuer cannot be built here, and that is worth
        /// knowing rather than working around: asking for a thirty-year leaf under a ten-year
        /// sub-CA produces a ten-year leaf, because the certificate factory clamps a certificate
        /// to its issuer's validity. So the shell model is checked from the other direction -
        /// past the whole chain's expiry, where the reason names the first certificate the walk
        /// reaches, and by revoking an intermediate, which the neighbouring test covers.
        /// </remarks>
        [Test]
        public void The_shell_model_covers_the_whole_path()
        {

            var vehicle    = pki.IssueProvisioningCertificate(pcid, TimeSpan.FromDays(365 * 30));

            var timestamp  = DateTimeOffset.UtcNow.AddDays(365 * 12);

            var result     = PnCChainValidator.Validate(vehicle.Certificate,
                                                        vehicle.SubCAs,
                                                        [ pki.OEMRoot.Certificate ],
                                                        timestamp);

            Assert.Multiple(() => {

                Assert.That(vehicle.Certificate.NotAfter,
                            Is.LessThanOrEqualTo(pki.OEMSubCA2.Certificate.NotAfter),
                            "A certificate is clamped to its issuer's validity.");

                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("is not valid at"));

            });

        }

        #endregion

        #region A_chain_missing_an_intermediate_is_refused()

        [Test]
        public void A_chain_missing_an_intermediate_is_refused()
        {

            var vehicle = pki.IssueProvisioningCertificate(pcid);

            var result  = PnCChainValidator.Validate(
                              vehicle.Certificate,
                              [ pki.OEMSubCA1.Certificate ],   // the issuing sub-CA is missing
                              [ pki.OEMRoot.Certificate ]
                          );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("neither a trusted root"));
            });

        }

        #endregion

        #region A_revoked_certificate_is_refused()

        [Test]
        public void A_revoked_certificate_is_refused()
        {

            var vehicle  = pki.IssueProvisioningCertificate(pcid);
            var revoked  = new HashSet<String> { vehicle.Certificate.SHA256Fingerprint };

            var result   = PnCChainValidator.Validate(
                               vehicle.Certificate,
                               vehicle.SubCAs,
                               [ pki.OEMRoot.Certificate ],
                               RevocationChecker: certificate => revoked.Contains(certificate.SHA256Fingerprint)
                           );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("has been revoked"));
            });

        }

        #endregion

        #region A_revoked_intermediate_takes_its_leaves_with_it()

        [Test]
        public void A_revoked_intermediate_takes_its_leaves_with_it()
        {

            var vehicle  = pki.IssueProvisioningCertificate(pcid);
            var revoked  = new HashSet<String> { pki.OEMSubCA2.Certificate.SHA256Fingerprint };

            var result   = PnCChainValidator.Validate(
                               vehicle.Certificate,
                               vehicle.SubCAs,
                               [ pki.OEMRoot.Certificate ],
                               RevocationChecker: certificate => revoked.Contains(certificate.SHA256Fingerprint)
                           );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("Sub-CA 2").And.Contains("revoked"));
            });

        }

        #endregion

        #region Validating_against_no_roots_at_all_is_refused()

        /// <summary>
        /// An empty trust store validates nothing. Answering "valid" would be the worst possible
        /// reading of "there is nothing to check against".
        /// </summary>
        [Test]
        public void Validating_against_no_roots_at_all_is_refused()
        {

            var vehicle = pki.IssueProvisioningCertificate(pcid);

            var result  = PnCChainValidator.Validate(vehicle.Certificate, vehicle.SubCAs, []);

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False);
                Assert.That(result.Reason,   Does.Contain("No trusted roots"));
            });

        }

        #endregion

        #region A_certificate_signed_by_a_different_key_under_the_same_name_is_refused()

        /// <summary>
        /// Two infrastructures built with the same names produce sub-CAs whose subject names
        /// match exactly and whose keys do not. Comparing names would accept this; only the
        /// signature refuses it.
        /// </summary>
        [Test]
        public void A_certificate_signed_by_a_different_key_under_the_same_name_is_refused()
        {

            var impostor = new PnCTestPKI();
            var vehicle  = impostor.IssueProvisioningCertificate(pcid);

            Assert.That(impostor.OEMSubCA2.Certificate.SubjectName,
                        Is.EqualTo(pki.OEMSubCA2.Certificate.SubjectName),
                        "Precondition: the names really are identical.");

            // The impostor's leaf and sub-CAs, but this ecosystem's root.
            var result = PnCChainValidator.Validate(
                             vehicle.Certificate,
                             vehicle.SubCAs,
                             [ pki.OEMRoot.Certificate ]
                         );

            Assert.Multiple(() => {
                Assert.That(result.IsValid,  Is.False, "A matching name is not a signature.");
                Assert.That(result.Reason,   Does.Contain("neither a trusted root"));
            });

        }

        #endregion

    }

}
