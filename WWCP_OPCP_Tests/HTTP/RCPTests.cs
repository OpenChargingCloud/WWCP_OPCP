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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// The Root Certificate Pool, client to server over a real socket.
    /// </summary>
    [TestFixture]
    public class RCPTests : AOPCPEcosystemTests
    {

        #region A_root_is_admitted_and_read_back()

        [Test]
        public async Task A_root_is_admitted_and_read_back()
        {

            var admin        = NewRCPClient(OPCPRole.Admin);
            var certificate  = NewRootCA("V2G Root CA Test");

            var added        = await admin.SaveRootCA(certificate, RootCertificateType.V2G);

            Assert.That(added.IsSuccess,  Is.True, added.Error?.ToString());
            Assert.That(added.Data,       Is.Not.Null, "Our pool answers with the stored entry.");

            var id           = added.Data!.Id;

            Assert.That(id,  Is.Not.Null, "A stored entry carries the identification the pool gave it.");

            var fetched      = await NewRCPClient(OPCPRole.CPO).GetRootCert(id!.Value);

            Assert.That(fetched.IsSuccess,  Is.True, fetched.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(fetched.Data!.Id,                       Is.EqualTo(id));
                Assert.That(fetched.Data.RootType,                  Is.EqualTo(RootCertificateType.V2G));
                Assert.That(fetched.Data.Certificate,               Is.EqualTo(certificate));
                Assert.That(fetched.Data.CommonName,                Is.EqualTo("V2G Root CA Test"));
                Assert.That(fetched.Data.Fingerprint,               Is.EqualTo(certificate.SHA256Fingerprint));
                Assert.That(fetched.Data.SignatureAlgorithm,        Is.EqualTo(SignatureAlgorithm.secp256r1));
            });

        }

        #endregion

        #region The_derived_fields_survive_the_wire(CurveName)

        /// <summary>
        /// Everything the pool publishes about a root is read from the certificate, so it has to
        /// come out the far side unchanged - including for Ed448, whose certificates are the
        /// reason this library parses through BouncyCastle at all.
        /// </summary>
        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        [TestCase("ed448")]
        public async Task The_derived_fields_survive_the_wire(String CurveName)
        {

            var admin        = NewRCPClient(OPCPRole.Admin);
            var certificate  = NewRootCA($"OEM Root CA {CurveName}", CurveName);

            var added        = await admin.SaveRootCA(certificate, RootCertificateType.OEM);
            Assert.That(added.IsSuccess,  Is.True, added.Error?.ToString());

            var fetched      = await admin.GetRootCert(added.Data!.Id!.Value);
            Assert.That(fetched.IsSuccess,  Is.True, fetched.Error?.ToString());

            var stored       = fetched.Data!;

            Assert.Multiple(() => {
                Assert.That(stored.DistinguishedName,       Is.EqualTo(certificate.SubjectName));
                Assert.That(stored.CommonName,              Is.EqualTo(certificate.CommonName));
                Assert.That(stored.RootIssuerSerialNumber,  Is.EqualTo(certificate.SerialNumber));
                Assert.That(stored.Fingerprint,             Is.EqualTo(certificate.SHA256Fingerprint));
                Assert.That(stored.FingerprintSha1,         Is.EqualTo(certificate.SHA1Fingerprint));
                Assert.That(stored.SignatureAlgorithm!.Value.ToString(),  Is.EqualTo(CurveName));

                // Timestamps go over the wire as ISO 8601 without fractions and must not drift.
                Assert.That(stored.ValidFrom,  Is.EqualTo(certificate.NotBefore));
                Assert.That(stored.ValidTo,    Is.EqualTo(certificate.NotAfter));

                // A self-signed root names itself, so both key identifiers are the same bytes.
                Assert.That(stored.RootAuthorityKeyIdentifier,
                            Is.EqualTo(certificate.AuthorityKeyIdentifier is not null
                                           ? Convert.ToBase64String(certificate.AuthorityKeyIdentifier)
                                           : null));
            });

        }

        #endregion

        #region The_pool_lists_what_it_holds_and_filters_by_trust_domain()

        [Test]
        public async Task The_pool_lists_what_it_holds_and_filters_by_trust_domain()
        {

            var admin = NewRCPClient(OPCPRole.Admin);

            await admin.SaveRootCA(NewRootCA("V2G Root One"),  RootCertificateType.V2G);
            await admin.SaveRootCA(NewRootCA("V2G Root Two"),  RootCertificateType.V2G);
            await admin.SaveRootCA(NewRootCA("OEM Root One"),  RootCertificateType.OEM);
            await admin.SaveRootCA(NewRootCA("MO Root One"),   RootCertificateType.MO);

            var reader   = NewRCPClient(OPCPRole.MO);

            var all      = await reader.GetAllRootCerts();
            var v2gOnly  = await reader.GetAllRootCerts(RootCertificateType.V2G);
            var moOnly   = await reader.GetAllRootCerts(RootCertificateType.MO);
            var peOnly   = await reader.GetAllRootCerts(RootCertificateType.PE);

            Assert.Multiple(() => {

                Assert.That(all.IsSuccess,      Is.True, all.Error?.ToString());
                Assert.That(all.Data,           Has.Exactly(4).Items);

                Assert.That(v2gOnly.Data,       Has.Exactly(2).Items);
                Assert.That(v2gOnly.Data!.Select(root => root.CommonName),
                            Is.EquivalentTo(new[] { "V2G Root One", "V2G Root Two" }));

                Assert.That(moOnly.Data,        Has.Exactly(1).Items);
                Assert.That(peOnly.Data,        Is.Empty, "Nothing was admitted as a PE root.");

            });

        }

        #endregion

        #region Either_spelling_of_the_trust_domain_filters_the_same(Spelling)

        /// <summary>
        /// The filter is documented lowercase ('mo', 'v2g', 'oem') while the value inside a
        /// certificate entry is uppercase. Both name one trust domain.
        /// </summary>
        [TestCase("v2g")]
        [TestCase("V2G")]
        [TestCase("V2g")]
        public async Task Either_spelling_of_the_trust_domain_filters_the_same(String Spelling)
        {

            var admin = NewRCPClient(OPCPRole.Admin);

            await admin.SaveRootCA(NewRootCA("V2G Root"), RootCertificateType.V2G);
            await admin.SaveRootCA(NewRootCA("OEM Root"), RootCertificateType.OEM);

            var filtered = await admin.GetAllRootCerts(RootCertificateType.Parse(Spelling));

            Assert.Multiple(() => {
                Assert.That(filtered.IsSuccess,  Is.True, filtered.Error?.ToString());
                Assert.That(filtered.Data,       Has.Exactly(1).Items);
                Assert.That(filtered.Data!.First().CommonName,  Is.EqualTo("V2G Root"));
                Assert.That(filtered.Data!.First().RootType.ToString(),  Is.EqualTo("V2G"), "Emitted uppercase whatever was asked for.");
            });

        }

        #endregion

        #region Admitting_the_same_root_twice_leaves_one_entry()

        /// <summary>
        /// A pool is a set of trust anchors. Two entries for one certificate would give
        /// participants two answers to "which roots do I trust", differing only in a UUID.
        /// </summary>
        [Test]
        public async Task Admitting_the_same_root_twice_leaves_one_entry()
        {

            var admin        = NewRCPClient(OPCPRole.Admin);
            var certificate  = NewRootCA("V2G Root CA Test");

            var first        = await admin.SaveRootCA(certificate, RootCertificateType.V2G);
            var second       = await admin.SaveRootCA(certificate, RootCertificateType.V2G);
            var all          = await admin.GetAllRootCerts();

            Assert.Multiple(() => {
                Assert.That(first.IsSuccess,   Is.True);
                Assert.That(second.IsSuccess,  Is.True);
                Assert.That(second.Data!.Id,   Is.EqualTo(first.Data!.Id), "The same entry came back.");
                Assert.That(all.Data,          Has.Exactly(1).Items);
            });

        }

        #endregion

        #region Deleting_a_root_removes_it()

        [Test]
        public async Task Deleting_a_root_removes_it()
        {

            var admin  = NewRCPClient(OPCPRole.Admin);
            var added  = await admin.SaveRootCA(NewRootCA("V2G Root CA Test"), RootCertificateType.V2G);
            var id     = added.Data!.Id!.Value;

            var gone   = await admin.DeleteRootCA(id);
            var lookup = await admin.GetRootCert(id);
            var again  = await admin.DeleteRootCA(id);

            Assert.Multiple(() => {
                Assert.That(gone.IsSuccess,        Is.True, gone.Error?.ToString());
                Assert.That(gone.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.OK));

                Assert.That(lookup.IsSuccess,      Is.False);
                Assert.That(lookup.HTTPStatusCode, Is.EqualTo(HTTPStatusCode.NotFound));

                Assert.That(again.IsSuccess,       Is.False, "Deleting it a second time finds nothing.");
                Assert.That(again.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
            });

        }

        #endregion

        #region An_unknown_root_is_a_404_carrying_a_trace_to_quote()

        [Test]
        public async Task An_unknown_root_is_a_404_carrying_a_trace_to_quote()
        {

            var response = await NewRCPClient(OPCPRole.CPO).GetRootCert(RootCertificate_Id.NewRandom());

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,       Is.False);
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("not found"));
                Assert.That(response.TraceId,         Is.Not.Null, "Every refusal names a trace.");
            });

        }

        #endregion


        #region Writing_is_reserved_for_an_administrator(Role)

        /// <summary>
        /// The roles and rights table gives write access to the pool to nobody but an
        /// administrator of the ecosystem - not even to the roles that read from it constantly.
        /// </summary>
        [TestCase("OEM")]
        [TestCase("CPO")]
        [TestCase("MO")]
        [TestCase("CPS")]
        public async Task Writing_is_reserved_for_an_administrator(String Role)
        {

            var client  = NewRCPClient(OPCPRole.Parse(Role));

            var added   = await client.SaveRootCA(NewRootCA("V2G Root CA Test"), RootCertificateType.V2G);
            var deleted = await client.DeleteRootCA(RootCertificate_Id.NewRandom());

            Assert.Multiple(() => {
                Assert.That(added.IsSuccess,        Is.False);
                Assert.That(added.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(added.Error!.FirstMessage,  Does.Contain("Admin"));

                Assert.That(deleted.IsSuccess,      Is.False);
                Assert.That(deleted.HTTPStatusCode, Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region Reading_is_open_to_every_role(Role)

        [TestCase("OEM")]
        [TestCase("CPO")]
        [TestCase("MO")]
        [TestCase("MO_HUBJECT_PKI")]
        [TestCase("MO_EXTERNAL_PKI")]
        [TestCase("CPS")]
        [TestCase("Admin")]
        public async Task Reading_is_open_to_every_role(String Role)
        {

            await NewRCPClient(OPCPRole.Admin).SaveRootCA(NewRootCA("V2G Root CA Test"), RootCertificateType.V2G);

            var response = await NewRCPClient(OPCPRole.Parse(Role)).GetAllRootCerts();

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,  Is.True, response.Error?.ToString());
                Assert.That(response.Data,       Has.Exactly(1).Items);
            });

        }

        #endregion

        #region A_request_without_a_token_is_refused()

        [Test]
        public async Task A_request_without_a_token_is_refused()
        {

            var anonymous = NewRCPClient();

            var listed    = await anonymous.GetAllRootCerts();
            var fetched   = await anonymous.GetRootCert(RootCertificate_Id.NewRandom());

            Assert.Multiple(() => {
                Assert.That(listed.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.Unauthorized));
                Assert.That(fetched.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));
                Assert.That(listed.Error!.FirstMessage,  Does.Contain("bearer token"));
            });

        }

        #endregion

        #region A_token_from_another_issuer_is_refused()

        [Test]
        public async Task A_token_from_another_issuer_is_refused()
        {

            var stranger = new TestTokenIssuer(baseURL);

            var client   = new RCP_HTTPClient(
                               baseURL,
                               new StaticAccessTokenProvider(stranger.IssueToken(Roles: [ OPCPRole.Admin ]).AccessToken)
                           );

            var response = await client.GetAllRootCerts();

            Assert.Multiple(() => {
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("signature"));
            });

        }

        #endregion


        #region A_certificate_that_cannot_anchor_anything_is_refused()

        /// <summary>
        /// A trust anchor has to be able to issue. Admitting a leaf certificate as a root would
        /// put something in the pool that no chain can ever validate against.
        /// </summary>
        [Test]
        public async Task A_certificate_that_cannot_anchor_anything_is_refused()
        {

            var keyPair  = PKIFactory.GenerateECCKeyPair();
            var rootCA   = PKIFactory.CreateRootCACertificate("Test Root", keyPair);

            var leafKey  = PKIFactory.GenerateECCKeyPair();
            var leaf     = PnCCertificate.From(
                               PKIFactory.SignClientCertificate(
                                   "Not A Root",
                                   leafKey.Public,
                                   keyPair.Private,
                                   rootCA
                               )
                           );

            var response = await NewRCPClient(OPCPRole.Admin).SaveRootCA(leaf, RootCertificateType.V2G);

            Assert.Multiple(() => {
                Assert.That(leaf.IsCertificateAuthority,   Is.False, "Precondition: this really is a leaf.");
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("certification authority"));
            });

        }

        #endregion

        #region Nonsense_in_place_of_a_certificate_is_refused()

        [Test]
        public async Task Nonsense_in_place_of_a_certificate_is_refused()
        {

            // Straight past the typed client, because the typed client would never let this out:
            // valid base64 that decodes to "Hello World!" rather than to a certificate.
            var response = await new RawOPCPClient(baseURL, TokenFor(OPCPRole.Admin)).
                                     SendRaw(HTTPMethod.PUT,
                                             "/v1/root/rootCerts",
                                             new JObject(
                                                 new JProperty("caCertificate",  "SGVsbG8gV29ybGQh"),
                                                 new JProperty("rootType",       "V2G")
                                             ));

            Assert.Multiple(() => {
                Assert.That(response.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.HTTPBodyAsUTF8String,  Does.Contain("errorMessages"));
                Assert.That(response.HTTPBodyAsUTF8String,  Does.Contain("traceId"));
            });

        }

        #endregion

        #region A_malformed_identification_in_the_path_is_refused()

        [Test]
        public async Task A_malformed_identification_in_the_path_is_refused()
        {

            var response = await new RawOPCPClient(baseURL, TokenFor(OPCPRole.CPO)).
                                     SendRaw(HTTPMethod.GET,
                                             "/v1/root/rootCerts/not-a-uuid");

            Assert.Multiple(() => {
                Assert.That(response.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.HTTPBodyAsUTF8String,  Does.Contain("not a valid root certificate identification"));
            });

        }

        #endregion

        #region The_trust_list_is_served_as_the_placeholder_it_is()

        /// <summary>
        /// OPCP 1.0.0 leaves the content of this endpoint "still to be aligned by stakeholders".
        /// It answers with the anchors it holds and a timestamp, and nothing pretends otherwise.
        /// </summary>
        [Test]
        public async Task The_trust_list_is_served_as_the_placeholder_it_is()
        {

            var admin = NewRCPClient(OPCPRole.Admin);
            await admin.SaveRootCA(NewRootCA("V2G Root CA Test"), RootCertificateType.V2G);

            var response = await admin.GetCertificateTrustList();

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,               Is.True, response.Error?.ToString());
                Assert.That(response.Data!["timeStamp"],      Is.Not.Null);
                Assert.That(response.Data!["CTL"],            Is.Not.Null);
            });

        }

        #endregion

    }

}
