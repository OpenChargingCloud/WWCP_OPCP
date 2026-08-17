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

using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.PKI
{

    /// <summary>
    /// The certificate signing requests enrollment is made of.
    /// </summary>
    [TestFixture]
    public class CSRBuilderTests
    {

        #region A_request_round_trips_and_proves_possession_of_its_key(Algorithm)

        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        [TestCase("ed448")]
        public void A_request_round_trips_and_proves_possession_of_its_key(String Algorithm)
        {

            var keyPair  = Algorithm == "ed448"
                               ? PKIFactory.GenerateEd448KeyPair()
                               : PKIFactory.GenerateECCKeyPair(Algorithm);

            var pcid     = PCID.Parse("ECD12345671234567");

            var csr      = CSRBuilder.CreateFor(pcid, keyPair, "GraphDefined GmbH", "DE");

            Assert.That(CSRBuilder.TryParse(csr.ToBase64(), out var parsed, out var errorResponse),  Is.True, errorResponse);

            Assert.That(parsed,  Is.Not.Null);

            Assert.Multiple(() => {
                Assert.That(parsed.GetCommonName(),  Is.EqualTo(pcid.ToString()));
                Assert.That(parsed.Verify(),         Is.True, "A request signs itself with the key it asks about.");
                Assert.That(csr.ToBase64(),          Is.EqualTo(parsed.ToBase64()));
            });

        }

        #endregion

        #region The_common_name_is_the_identifier_being_certified()

        /// <summary>
        /// The certification authority refuses a request whose common name is not the identifier
        /// it was asked to certify, so getting this right is the whole content of a request.
        /// </summary>
        [Test]
        public void The_common_name_is_the_identifier_being_certified()
        {

            var keyPair   = PKIFactory.GenerateECCKeyPair();

            var vehicle   = CSRBuilder.CreateFor(PCID.  Parse("ECD12345671234567"), keyPair);
            var contract  = CSRBuilder.CreateFor(EMA_Id.Parse("DE-ECD-123456789"),  keyPair);
            var station   = CSRBuilder.Create   ("DE*ICE*E45B*78C",                 keyPair);

            Assert.Multiple(() => {
                Assert.That(vehicle. GetCommonName(),  Is.EqualTo("ECD12345671234567"));
                Assert.That(contract.GetCommonName(),  Is.EqualTo("DEECD123456789"), "Normalized, as the ecosystem stores it.");
                Assert.That(station. GetCommonName(),  Is.EqualTo("DE*ICE*E45B*78C"));
            });

        }

        #endregion

        #region A_request_can_be_signed_into_a_certificate()

        /// <summary>
        /// What enrollment actually does with one: hand it to a certification authority and get
        /// back a certificate naming the same subject and carrying the same public key.
        /// </summary>
        [Test]
        public void A_request_can_be_signed_into_a_certificate()
        {

            var pki      = new PnCTestPKI();
            var keyPair  = PKIFactory.GenerateECCKeyPair();
            var pcid     = PCID.Parse("ECD12345671234567");

            var csr      = CSRBuilder.CreateFor(pcid, keyPair, "GraphDefined GmbH", "DE");

            var issued   = PnCCertificate.From(
                               PKIFactory.SignClientCertificate(
                                   csr.GetCommonName(),
                                   csr.GetPublicKey(),
                                   pki.OEMSubCA2.PrivateKey,
                                   pki.OEMSubCA2.Certificate.BouncyCastleCertificate
                               )
                           );

            var result   = PnCChainValidator.ValidateProvisioningCertificate(
                               issued,
                               [ pki.OEMSubCA2.Certificate, pki.OEMSubCA1.Certificate ],
                               [ pki.OEMRoot.Certificate ],
                               pcid
                           );

            Assert.Multiple(() => {
                Assert.That(issued.CommonName,  Is.EqualTo(pcid.ToString()));
                Assert.That(result.IsValid,     Is.True, result.Reason);
                Assert.That(result.Anchor,      Is.EqualTo(pki.OEMRoot.Certificate));
            });

        }

        #endregion

        #region A_request_with_a_broken_signature_is_refused()

        /// <summary>
        /// Without the self-signature a request proves nothing: anyone could ask for a certificate
        /// on a public key whose private half they do not hold.
        /// </summary>
        [Test]
        public void A_request_with_a_broken_signature_is_refused()
        {

            var csr    = CSRBuilder.Create("ECD12345671234567", PKIFactory.GenerateECCKeyPair());
            var bytes  = csr.GetEncoded();

            // Corrupt the signature at the very end of the structure.
            bytes[^1] ^= 0xFF;
            bytes[^2] ^= 0xFF;

            Assert.Multiple(() => {
                Assert.That(CSRBuilder.TryParse(Convert.ToBase64String(bytes), out _, out var why),  Is.False);
                Assert.That(why,  Is.Not.Null.And.Not.Empty);
            });

        }

        #endregion

        #region Nonsense_in_place_of_a_request_is_refused(Base64)

        [TestCase("",                  Description = "empty")]
        [TestCase("   ",               Description = "whitespace")]
        [TestCase("not base64 at all", Description = "not base64")]
        [TestCase("SGVsbG8gV29ybGQh",  Description = "valid base64, but not a request")]
        public void Nonsense_in_place_of_a_request_is_refused(String Base64)
        {

            Assert.Multiple(() => {
                Assert.That(CSRBuilder.TryParse(Base64, out var csr, out var why),  Is.False);
                Assert.That(csr,  Is.Null);
                Assert.That(why,  Is.Not.Null.And.Not.Empty);
            });

        }

        #endregion

        #region A_request_without_a_subject_is_refused()

        [Test]
        public void A_request_without_a_subject_is_refused()
        {

            Assert.That(() => CSRBuilder.Create("", PKIFactory.GenerateECCKeyPair()),
                        Throws.ArgumentException);

        }

        #endregion

    }

}
