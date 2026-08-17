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
    /// The three certificate hierarchies that meet in a vehicle.
    /// </summary>
    [TestFixture]
    public class PnCTestPKITests
    {

        #region The_three_hierarchies_are_built_and_separate(Algorithm)

        /// <summary>
        /// All three curves OPCP names, including Ed448 - which the platform's own chain engine
        /// may not handle, and which is why nothing here goes through it.
        /// </summary>
        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        [TestCase("ed448")]
        public void The_three_hierarchies_are_built_and_separate(String Algorithm)
        {

            var pki = new PnCTestPKI(SignatureAlgorithm.Parse(Algorithm));

            Assert.Multiple(() => {

                // Every root is a self-signed authority on the requested curve.
                foreach (var root in new[] { pki.V2GRoot, pki.OEMRoot, pki.MORoot, pki.UntrustedRoot })
                {
                    Assert.That(root.Certificate.IsCertificateAuthority,               Is.True,  $"{root} must be a CA.");
                    Assert.That(root.Certificate.IssuerName,                           Is.EqualTo(root.Certificate.SubjectName), $"{root} must be self-signed.");
                    Assert.That(root.Certificate.SignatureAlgorithm!.Value.ToString(), Is.EqualTo(Algorithm));
                    Assert.That(root.Issuer,                                           Is.Null);
                    Assert.That(root.Root,                                             Is.SameAs(root));
                }

                // The roots are genuinely different anchors, not one certificate under four names.
                var fingerprints = new[] { pki.V2GRoot, pki.OEMRoot, pki.MORoot, pki.UntrustedRoot }.
                                       Select(root => root.Certificate.SHA256Fingerprint);

                Assert.That(fingerprints.Distinct(),  Has.Exactly(4).Items);

            });

        }

        #endregion

        #region Every_sub_CA_chains_to_the_root_it_belongs_to()

        [Test]
        public void Every_sub_CA_chains_to_the_root_it_belongs_to()
        {

            var pki = new PnCTestPKI();

            Assert.Multiple(() => {

                // The V2G root anchors the charging infrastructure, contract signing, and
                // operators without a PKI of their own.
                Assert.That(pki.CPOSubCA2.  Root,  Is.SameAs(pki.V2GRoot));
                Assert.That(pki.CPSSubCA2.  Root,  Is.SameAs(pki.V2GRoot));
                Assert.That(pki.V2GMOSubCA2.Root,  Is.SameAs(pki.V2GRoot));

                // The manufacturers and an operator's own PKI are separate anchors.
                Assert.That(pki.OEMSubCA2.  Root,  Is.SameAs(pki.OEMRoot));
                Assert.That(pki.MOSubCA2.   Root,  Is.SameAs(pki.MORoot));

                // ISO 15118-2's shape: root, sub-CA 1, sub-CA 2.
                Assert.That(pki.OEMSubCA2.Chain,   Has.Exactly(3).Items);
                Assert.That(pki.OEMSubCA1.Chain,   Has.Exactly(2).Items);

                foreach (var subCA in new[] { pki.CPOSubCA1, pki.CPOSubCA2, pki.OEMSubCA1, pki.OEMSubCA2 })
                    Assert.That(subCA.Certificate.IsCertificateAuthority,  Is.True, $"{subCA} must be a CA.");

            });

        }

        #endregion

        #region A_leaf_is_named_by_the_thing_it_identifies()

        /// <summary>
        /// In ISO 15118 the common name of a leaf certificate is the identifier itself. Nothing
        /// else in the certificate carries it, which is why validating one means comparing the
        /// common name against what was asked for.
        /// </summary>
        [Test]
        public void A_leaf_is_named_by_the_thing_it_identifies()
        {

            var pki       = new PnCTestPKI();

            var pcid      = PCID.  Parse("ECD12345671234567");
            var emaId     = EMA_Id.Parse("DEECD123456789");

            var vehicle   = pki.IssueProvisioningCertificate(pcid);
            var contract  = pki.IssueContractCertificate(emaId);
            var ownPKI    = pki.IssueContractCertificate(emaId, OwnPKI: true);
            var secc      = pki.IssueSECCCertificate("DE*ICE*E45B*78C");
            var signer    = pki.IssueCPSSigningCertificate();

            Assert.Multiple(() => {

                Assert.That(vehicle.Certificate.CommonName,   Is.EqualTo(pcid.ToString()));
                Assert.That(vehicle.Root,                     Is.SameAs(pki.OEMRoot));
                Assert.That(vehicle.Certificate.IsCertificateAuthority,  Is.False, "A leaf must not be able to issue.");

                Assert.That(contract.Certificate.CommonName,  Is.EqualTo(emaId.ToString()));
                Assert.That(contract.Root,                    Is.SameAs(pki.V2GRoot), "An operator without its own PKI is issued under the V2G root.");

                Assert.That(ownPKI.Certificate.CommonName,    Is.EqualTo(emaId.ToString()));
                Assert.That(ownPKI.Root,                      Is.SameAs(pki.MORoot),  "An operator with its own PKI is issued under it.");

                Assert.That(secc.Certificate.CommonName,      Is.EqualTo("DE*ICE*E45B*78C"));
                Assert.That(secc.Root,                        Is.SameAs(pki.V2GRoot));

                Assert.That(signer.Certificate.CommonName,    Is.EqualTo("CPS Provisioning Signer"));
                Assert.That(signer.Root,                      Is.SameAs(pki.V2GRoot));

                // The specification's own example gives a CPS signer three months. The span comes
                // out slightly longer than the requested lifetime because certificates are issued
                // with their validity starting a little in the past, so that a verifier whose
                // clock runs behind does not reject a certificate that was just issued.
                Assert.That(signer.Certificate.NotAfter - signer.Certificate.NotBefore,
                            Is.EqualTo(TimeSpan.FromDays(90)).Within(TimeSpan.FromHours(2)));

            });

        }

        #endregion

        #region A_leaf_carries_its_sub_CAs_but_not_its_root()

        /// <summary>
        /// This is exactly what OPCP transports: the provisioning certificate pool is given the
        /// leaf and its sub-CAs, and derives the root itself - because the root is something the
        /// recipient is supposed to already have from the root certificate pool.
        /// </summary>
        [Test]
        public void A_leaf_carries_its_sub_CAs_but_not_its_root()
        {

            var pki      = new PnCTestPKI();
            var vehicle  = pki.IssueProvisioningCertificate(PCID.Parse("ECD12345671234567"));

            Assert.Multiple(() => {

                Assert.That(vehicle.Chain,   Has.Exactly(4).Items, "leaf, sub-CA 2, sub-CA 1, root");
                Assert.That(vehicle.SubCAs,  Has.Exactly(2).Items);

                Assert.That(vehicle.SubCAs.First(),  Is.EqualTo(pki.OEMSubCA2.Certificate), "Nearest first.");
                Assert.That(vehicle.SubCAs.Last(),   Is.EqualTo(pki.OEMSubCA1.Certificate));
                Assert.That(vehicle.SubCAs,          Has.No.Member(pki.OEMRoot.Certificate), "The root is not carried.");

                Assert.That(vehicle.Chain.Last(),    Is.EqualTo(pki.OEMRoot.Certificate));

            });

        }

        #endregion

        #region Two_infrastructures_share_nothing()

        [Test]
        public void Two_infrastructures_share_nothing()
        {

            var one      = new PnCTestPKI(Name: "One");
            var another  = new PnCTestPKI(Name: "Two");

            Assert.Multiple(() => {
                Assert.That(one.V2GRoot.Certificate,  Is.Not.EqualTo(another.V2GRoot.Certificate));
                Assert.That(one.V2GRoot.Certificate.CommonName,  Does.Contain("One"));
                Assert.That(another.V2GRoot.Certificate.CommonName,  Does.Contain("Two"));
            });

        }

        #endregion

    }

}
