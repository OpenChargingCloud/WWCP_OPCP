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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.PKI
{

    /// <summary>
    /// Asking a responder whether a certificate is still good, over HTTP, as RFC 6960 describes.
    ///
    /// The Plug&amp;Charge ecosystem leans on this in more places than it looks: publishing a
    /// vehicle's certificate checks it, handing that certificate out checks it again, and a
    /// mobility operator checks it before concluding a contract.
    /// </summary>
    [TestFixture]
    public class OCSPTests : AOPCPEcosystemTests
    {

        #region Setup

        [SetUp]
        public void ForgetRevocations()
        {
            foreach (var certificate in issued)
                oemResponder.Unrevoke(certificate);

            issued.Clear();
        }

        private readonly List<PnCCertificate> issued = [];

        private IssuedCertificate NewVehicle(String PCIDText = "ECD12345671234567")
        {
            var vehicle = pki.IssueProvisioningCertificate(PCID.Parse(PCIDText));
            issued.Add(vehicle.Certificate);
            return vehicle;
        }

        #endregion


        #region A_certificate_nobody_revoked_is_good()

        [Test]
        public async Task A_certificate_nobody_revoked_is_good()
        {

            var vehicle  = NewVehicle();
            var client   = new OCSPClient(ocspURL);

            var result   = await client.CheckStatus(vehicle.Certificate,
                                                    pki.OEMSubCA2.Certificate);

            Assert.Multiple(() => {
                Assert.That(result.Status,     Is.EqualTo(OCSPCertificateStatus.Good), result.Reason);
                Assert.That(result.IsGood,     Is.True);
                Assert.That(result.IsRevoked,  Is.False);
                Assert.That(result.RevokedAt,  Is.Null);
            });

        }

        #endregion

        #region A_revoked_certificate_is_reported_with_its_reason()

        [Test]
        public async Task A_revoked_certificate_is_reported_with_its_reason()
        {

            var vehicle    = NewVehicle();
            var revokedAt  = DateTimeOffset.UtcNow.AddHours(-3);

            oemResponder.Revoke(vehicle.Certificate,
                                RevocationReason.KeyCompromise,
                                revokedAt);

            var result     = await new OCSPClient(ocspURL).CheckStatus(vehicle.Certificate,
                                                                       pki.OEMSubCA2.Certificate);

            Assert.Multiple(() => {
                Assert.That(result.Status,            Is.EqualTo(OCSPCertificateStatus.Revoked), result.Reason);
                Assert.That(result.IsRevoked,         Is.True);
                Assert.That(result.RevocationReason,  Is.EqualTo(RevocationReason.KeyCompromise));
                Assert.That(result.RevokedAt,         Is.EqualTo(revokedAt).Within(TimeSpan.FromSeconds(1)));
            });

        }

        #endregion

        #region Revoking_one_certificate_leaves_the_others_alone()

        [Test]
        public async Task Revoking_one_certificate_leaves_the_others_alone()
        {

            var one      = NewVehicle("ECD11111111111111");
            var another  = NewVehicle("ECD22222222222222");

            oemResponder.Revoke(one.Certificate);

            var client   = new OCSPClient(ocspURL);

            var first    = await client.CheckStatus(one.    Certificate, pki.OEMSubCA2.Certificate);
            var second   = await client.CheckStatus(another.Certificate, pki.OEMSubCA2.Certificate);

            Assert.Multiple(() => {
                Assert.That(first.IsRevoked,   Is.True);
                Assert.That(second.IsGood,     Is.True, second.Reason);
                Assert.That(oemResponder.RevokedCount,  Is.EqualTo(1));
            });

        }

        #endregion

        #region An_answer_signed_by_the_wrong_authority_is_not_believed()

        /// <summary>
        /// The response is genuine, well-formed and about the right serial - and signed by an
        /// authority that has no business answering for this certificate. Accepting it would let
        /// anyone with a responder vouch for anyone else's certificates.
        /// </summary>
        [Test]
        public async Task An_answer_signed_by_the_wrong_authority_is_not_believed()
        {

            var vehicle = NewVehicle();

            var result  = await new OCSPClient(ocspURL).CheckStatus(
                                    vehicle.Certificate,
                                    pki.CPOSubCA2.Certificate   // answers are signed by the OEM sub-CA, not this one
                                );

            Assert.Multiple(() => {
                Assert.That(result.Status,  Is.EqualTo(OCSPCertificateStatus.Unknown));
                Assert.That(result.Reason,  Does.Contain("not signed by the issuing authority"));
                Assert.That(result.IsGood,  Is.False, "Not knowing is never the same as good.");
            });

        }

        #endregion

        #region An_unreachable_responder_is_unknown_rather_than_good()

        /// <summary>
        /// The distinction the whole design turns on: a revocation check that could not be made
        /// has not passed. What to do about it is the caller's decision - the specification has
        /// the pools refuse - but it must never look like approval.
        /// </summary>
        [Test]
        public async Task An_unreachable_responder_is_unknown_rather_than_good()
        {

            var vehicle = NewVehicle();

            // A port nothing is listening on.
            var client  = new OCSPClient(URL.Parse("http://127.0.0.1:1/ocsp/"),
                                         RequestTimeout: TimeSpan.FromSeconds(2));

            var result  = await client.CheckStatus(vehicle.Certificate,
                                                   pki.OEMSubCA2.Certificate);

            Assert.Multiple(() => {
                Assert.That(result.Status,     Is.EqualTo(OCSPCertificateStatus.Unknown));
                Assert.That(result.IsGood,     Is.False);
                Assert.That(result.Reason,     Is.Not.Empty);
            });

        }

        #endregion

        #region Nonsense_in_place_of_a_request_gets_an_OCSP_answer_not_an_HTTP_error()

        /// <summary>
        /// RFC 6960 has a responder answer a malformed request with an OCSP response saying so.
        /// A client that speaks OCSP rather than HTTP can read that; an HTTP error it cannot.
        /// </summary>
        [Test]
        public void Nonsense_in_place_of_a_request_gets_an_OCSP_answer_not_an_HTTP_error()
        {

            var answer = oemResponder.Respond("this is not an OCSP request"u8.ToArray());

            Assert.Multiple(() => {
                Assert.That(answer,  Is.Not.Null.And.Not.Empty);
                Assert.That(() => new Org.BouncyCastle.Ocsp.OcspResp(answer),  Throws.Nothing,
                            "Whatever it says, it has to be a readable OCSP response.");
                Assert.That(new Org.BouncyCastle.Ocsp.OcspResp(answer).Status,
                            Is.EqualTo(Org.BouncyCastle.Ocsp.OcspRespStatus.MalformedRequest));
            });

        }

        #endregion

        #region The_responder_feeds_the_chain_validator()

        /// <summary>
        /// The two halves of phase 3 together, which is how the provisioning certificate pool will
        /// use them: a chain that validates until its leaf is revoked.
        /// </summary>
        [Test]
        public async Task The_responder_feeds_the_chain_validator()
        {

            var vehicle  = NewVehicle();
            var client   = new OCSPClient(ocspURL);

            // The pool asks the responder about each certificate as it walks the path.
            async Task<ChainValidationResult> Validate()
            {

                var revoked = new HashSet<String>();

                foreach (var certificate in new[] { vehicle.Certificate, pki.OEMSubCA2.Certificate })
                {

                    var issuer  = certificate == vehicle.Certificate
                                      ? pki.OEMSubCA2.Certificate
                                      : pki.OEMSubCA1.Certificate;

                    var status  = await client.CheckStatus(certificate, issuer);

                    if (status.IsRevoked)
                        revoked.Add(certificate.SHA256Fingerprint);

                }

                return PnCChainValidator.ValidateProvisioningCertificate(
                           vehicle.Certificate,
                           vehicle.SubCAs,
                           [ pki.OEMRoot.Certificate ],
                           PCID.Parse("ECD12345671234567"),
                           RevocationChecker: certificate => revoked.Contains(certificate.SHA256Fingerprint)
                       );

            }

            var before = await Validate();

            oemResponder.Revoke(vehicle.Certificate, RevocationReason.CessationOfOperation);

            var after  = await Validate();

            Assert.Multiple(() => {
                Assert.That(before.IsValid,  Is.True, before.Reason);
                Assert.That(after.IsValid,   Is.False);
                Assert.That(after.Reason,    Does.Contain("revoked"));
            });

        }

        #endregion

    }

}
