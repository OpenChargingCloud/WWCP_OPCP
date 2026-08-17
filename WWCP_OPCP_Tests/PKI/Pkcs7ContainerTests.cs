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
    /// The envelope RFC 7030 answers enrollment with: a CMS signed-data with no signers, whose
    /// entire purpose is to be a list of certificates that survives being sent as one blob.
    /// </summary>
    [TestFixture]
    public class Pkcs7ContainerTests
    {

        #region Data

        private static PnCTestPKI       pki       = null!;
        private static IssuedCertificate  station = null!;

        [OneTimeSetUp]
        public void BuildPKI()
        {
            pki      = new PnCTestPKI();
            station  = pki.IssueSECCCertificate("DE*ICE*E45B*78C");
        }

        #endregion


        #region A_chain_survives_the_round_trip()

        [Test]
        public void A_chain_survives_the_round_trip()
        {

            var chain     = station.Chain.ToArray();

            var container = Pkcs7CertificateContainer.Create(chain);

            Assert.That(Pkcs7CertificateContainer.TryParse(container, out var read, out var why),
                        Is.True, why);

            Assert.Multiple(() => {

                Assert.That(read,  Has.Exactly(chain.Length).Items);

                Assert.That(read!.Select(certificate => certificate.SHA256Fingerprint),
                            Is.EquivalentTo(chain.Select(certificate => certificate.SHA256Fingerprint)));

            });

        }

        #endregion

        #region The_chain_comes_back_leaf_first_although_the_format_does_not_keep_an_order()

        /// <summary>
        /// The certificates live in an ASN.1 SET OF, and DER sorts the members of a set by their
        /// own encoding - so whatever order they were written in is gone. The reader puts the
        /// chain back together the way a verifier would: the certificate nothing else was issued
        /// by is the leaf, and each one after it issued the one before.
        /// </summary>
        [Test]
        public void The_chain_comes_back_leaf_first_although_the_format_does_not_keep_an_order()
        {

            // Written deliberately backwards, root first.
            var container = Pkcs7CertificateContainer.Create(station.Chain.Reverse());

            Assert.That(Pkcs7CertificateContainer.TryParse(container, out var read, out var why),
                        Is.True, why);

            Assert.Multiple(() => {

                Assert.That(read![0].CommonName,   Is.EqualTo("DE*ICE*E45B*78C"));
                Assert.That(read[^1].SubjectName,  Is.EqualTo(read[^1].IssuerName),
                            "The last one is self-signed, which is where every chain ends.");

            });

        }

        #endregion

        #region A_single_certificate_needs_no_ordering()

        [Test]
        public void A_single_certificate_needs_no_ordering()
        {

            var container = Pkcs7CertificateContainer.Create(station.Certificate);

            Assert.That(Pkcs7CertificateContainer.TryParse(container, out var read, out var why),
                        Is.True, why);

            Assert.That(read,  Has.Exactly(1).Items);

        }

        #endregion

        #region Base64_and_PEM_armour_are_both_read()

        /// <summary>
        /// A client that has a structure in a file has it with a header, a footer and line breaks.
        /// </summary>
        [Test]
        public void Base64_and_PEM_armour_are_both_read()
        {

            var base64    = Pkcs7CertificateContainer.ToBase64(station.Chain);

            var armoured  = "-----BEGIN PKCS7-----\r\n" + base64 + "\r\n-----END PKCS7-----\r\n";

            Assert.Multiple(() => {
                Assert.That(Pkcs7CertificateContainer.TryParse(base64,   out _, out _),  Is.True);
                Assert.That(Pkcs7CertificateContainer.TryParse(armoured, out _, out _),  Is.True);
            });

        }

        #endregion

        #region Nothing_that_is_not_one_is_read_as_one()

        [Test]
        public void Nothing_that_is_not_one_is_read_as_one()
        {

            Assert.Multiple(() => {

                Assert.That(Pkcs7CertificateContainer.TryParse("",                out _, out _),  Is.False);
                Assert.That(Pkcs7CertificateContainer.TryParse("not base64 at $$", out _, out _),  Is.False);

                // Well-formed base64 of something that is not a PKCS#7 structure.
                Assert.That(Pkcs7CertificateContainer.TryParse(Convert.ToBase64String([ 1, 2, 3, 4 ]), out _, out _),
                            Is.False);

                // A container of nothing would say nothing.
                Assert.That(() => Pkcs7CertificateContainer.Create([]),
                            Throws.ArgumentException);

            });

        }

        #endregion

    }

}
