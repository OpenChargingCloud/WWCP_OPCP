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

using System.Globalization;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.DataStructures
{

    /// <summary>
    /// The certificate wrapper is checked against a certificate the specification publishes
    /// together with the values it derives from it - the fingerprint, the key identifier, the
    /// serial number, the validity. Reproducing those from the certificate alone is the whole
    /// point: it proves this library reads a certificate the way the ecosystem does, rather than
    /// proving that a string was copied correctly.
    /// </summary>
    [TestFixture]
    public class PnCCertificateTests
    {

        #region Data

        private JObject vector = [];

        [OneTimeSetUp]
        public void LoadVector()
        {
            vector = Vectors.Load("rcp-v2g-root-ca-g2.json");
        }

        /// <summary>
        /// Parse an ISO 8601 timestamp independently of the machine's locale and time zone.
        /// Both halves matter: the invariant culture keeps "2019-01-10" from being read as the
        /// first of October under a German locale, and adjusting to universal keeps the trailing
        /// Z from being re-expressed in the local offset.
        /// </summary>
        private static DateTimeOffset ParseTimestamp(String Text)

            => DateTimeOffset.Parse(Text,
                                    CultureInfo.InvariantCulture,
                                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

        #endregion


        #region The_specifications_own_derived_values_are_reproduced()

        [Test]
        public void The_specifications_own_derived_values_are_reproduced()
        {

            var certificate = PnCCertificate.Parse(Vectors.GetString(vector, "caCertificate"));

            Assert.Multiple(() => {

                Assert.That(certificate.CommonName,
                            Is.EqualTo(Vectors.GetString(vector, "commonName")));

                Assert.That(certificate.SerialNumber,
                            Is.EqualTo(Vectors.GetString(vector, "rootIssuerSerialNumber")));

                Assert.That(certificate.SHA256Fingerprint,
                            Is.EqualTo(Vectors.GetString(vector, "fingerprint")));

                Assert.That(certificate.NotBefore,
                            Is.EqualTo(ParseTimestamp(Vectors.GetString(vector, "validFrom"))));

                Assert.That(certificate.NotAfter,
                            Is.EqualTo(ParseTimestamp(Vectors.GetString(vector, "validTo"))));

                // A self-signed root: it issues, and it names itself as its own issuer.
                Assert.That(certificate.IsCertificateAuthority,  Is.True);
                Assert.That(certificate.IssuerName,              Is.EqualTo(certificate.SubjectName));

            });

        }

        #endregion

        #region The_key_identifier_is_offered_in_all_three_encodings_OPCP_uses()

        /// <summary>
        /// The root certificate pool publishes this key identifier as base64 and the provisioning
        /// certificate pool publishes the same eight bytes as colon-separated hexadecimal. Both
        /// spellings have to come out of the one certificate.
        /// </summary>
        [Test]
        public void The_key_identifier_is_offered_in_all_three_encodings_OPCP_uses()
        {

            var certificate = PnCCertificate.Parse(Vectors.GetString(vector, "caCertificate"));
            var keyId       = certificate.AuthorityKeyIdentifier;

            Assert.That(keyId,  Is.Not.Null);

            Assert.Multiple(() => {

                Assert.That(Convert.ToBase64String(keyId!),
                            Is.EqualTo(Vectors.GetString(vector, "rootAuthorityKeyIdentifier")),
                            "The base64 encoding used by the root certificate pool.");

                Assert.That(PnCCertificate.ToHex(keyId),
                            Is.EqualTo("45b8409ee138f8bf"),
                            "Plain lowercase hexadecimal.");

                Assert.That(PnCCertificate.ToHex(keyId, ":"),
                            Is.EqualTo("45:b8:40:9e:e1:38:f8:bf"),
                            "The colon-separated form used by the provisioning certificate pool.");

                // ISO 15118 truncates key identifiers to eight bytes rather than using the
                // full SHA-1 of the public key.
                Assert.That(keyId,  Has.Length.EqualTo(8));

                // Self-signed: the authority key identifier is its own subject key identifier.
                Assert.That(certificate.SubjectKeyIdentifier,  Is.EqualTo(keyId));

            });

        }

        #endregion

        #region The_distinguished_name_matches_the_specifications_pattern()

        /// <summary>
        /// The root certificate pool constrains this field with
        /// <c>^((CN|OU|O|C|DC|ST)=[^,]+,? ?)+$</c>, which permits the components to be separated
        /// by a comma with or without a following space. What matters is the order - most specific
        /// component first - not the whitespace.
        /// </summary>
        [Test]
        public void The_distinguished_name_matches_the_specifications_pattern()
        {

            var certificate = PnCCertificate.Parse(Vectors.GetString(vector, "caCertificate"));
            var expected    = Vectors.GetString(vector, "distinguishedName");

            Assert.Multiple(() => {

                Assert.That(certificate.SubjectName,
                            Is.EqualTo("CN=V2G Root CA G2,DC=V2G,O=Hubject GmbH,C=DE"));

                Assert.That(certificate.SubjectName.Replace(",", ", "),
                            Is.EqualTo(expected),
                            "Modulo the optional space, this is the name the specification prints.");

                Assert.That(certificate.SubjectName,
                            Does.Match(@"^((CN|OU|O|C|DC|ST)=[^,]+,? ?)+$"));

            });

        }

        #endregion

        #region Validity_is_answered_against_a_moment_in_time()

        [Test]
        public void Validity_is_answered_against_a_moment_in_time()
        {

            var certificate = PnCCertificate.Parse(Vectors.GetString(vector, "caCertificate"));

            Assert.Multiple(() => {
                Assert.That(certificate.IsValidAt(DateTimeOffset.Parse("2030-01-01T00:00:00Z")),  Is.True);
                Assert.That(certificate.IsValidAt(DateTimeOffset.Parse("2018-01-01T00:00:00Z")),  Is.False, "Before it was issued.");
                Assert.That(certificate.IsValidAt(DateTimeOffset.Parse("2060-01-01T00:00:00Z")),  Is.False, "After it expires.");
                Assert.That(certificate.IsValidAt(certificate.NotBefore),                         Is.True,  "The boundaries are inclusive.");
                Assert.That(certificate.IsValidAt(certificate.NotAfter),                          Is.True);
            });

        }

        #endregion

        #region The_wire_encoding_is_kept_and_re_encodes_identically()

        [Test]
        public void The_wire_encoding_is_kept_and_re_encodes_identically()
        {

            var base64       = Vectors.GetString(vector, "caCertificate");
            var certificate  = PnCCertificate.Parse(base64);

            Assert.Multiple(() => {
                Assert.That(certificate.Base64,                         Is.EqualTo(base64));
                Assert.That(Convert.ToBase64String(certificate.DER),    Is.EqualTo(base64));
                Assert.That(PnCCertificate.FromDER(certificate.DER),    Is.EqualTo(certificate));
                Assert.That(certificate.ToPEM(),                        Does.StartWith("-----BEGIN CERTIFICATE-----"));
            });

        }

        #endregion

        #region Malformed_certificates_are_rejected_with_a_reason(Base64, Because)

        [TestCase("",                   "empty")]
        [TestCase("   ",                "whitespace only")]
        [TestCase("not base64 at all!", "not base64")]
        [TestCase("SGVsbG8gV29ybGQh",   "valid base64, but not a certificate")]
        public void Malformed_certificates_are_rejected_with_a_reason(String Base64, String Because)
        {

            Assert.Multiple(() => {

                Assert.That(PnCCertificate.TryParse(Base64, out var certificate, out var errorResponse),  Is.False, Because);
                Assert.That(certificate,    Is.Null);
                Assert.That(errorResponse,  Is.Not.Null.And.Not.Empty, "A rejection must say why.");

                Assert.That(PnCCertificate.TryParse(Base64),   Is.Null);
                Assert.That(() => PnCCertificate.Parse(Base64), Throws.ArgumentException);

            });

        }

        #endregion

        #region A_freshly_minted_certificate_is_read_back(CurveName)

        /// <summary>
        /// The specification's example is one ECDSA P-256 certificate frozen in 2019. This covers
        /// the rest of what OPCP admits - including Ed448, which is the reason certificates are
        /// parsed through BouncyCastle rather than through the platform.
        /// </summary>
        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        [TestCase("ed448")]
        public void A_freshly_minted_certificate_is_read_back(String CurveName)
        {

            var keyPair      = CurveName == "ed448"
                                   ? PKIFactory.GenerateEd448KeyPair()
                                   : PKIFactory.GenerateECCKeyPair(CurveName);

            // Hermod's factory builds the subject as "CN={SubjectName}", so this parameter
            // is the common name itself rather than a whole distinguished name.
            var rootCA       = PKIFactory.CreateRootCACertificate(
                                   SubjectName:  "WWCP OPCP Test Root",
                                   RootKeyPair:  keyPair
                               );

            var certificate  = PnCCertificate.From(rootCA);

            Assert.Multiple(() => {
                Assert.That(certificate.CommonName,              Is.EqualTo("WWCP OPCP Test Root"));
                Assert.That(certificate.IsCertificateAuthority,  Is.True);
                Assert.That(certificate.SHA256Fingerprint,       Has.Length.EqualTo(64));
                Assert.That(certificate.SHA1Fingerprint,         Has.Length.EqualTo(40));
                Assert.That(certificate.IsValidAt(DateTimeOffset.UtcNow),  Is.True);

                // Round-trip through the wire encoding.
                Assert.That(PnCCertificate.Parse(certificate.Base64),  Is.EqualTo(certificate));
            });

        }

        #endregion

        #region Two_certificates_are_the_same_when_their_bytes_are()

        [Test]
        public void Two_certificates_are_the_same_when_their_bytes_are()
        {

            var base64  = Vectors.GetString(vector, "caCertificate");
            var one     = PnCCertificate.Parse(base64);
            var another = PnCCertificate.Parse(base64);

            Assert.Multiple(() => {
                Assert.That(one,                Is.EqualTo(another));
                Assert.That(one == another,     Is.True);
                Assert.That(one.GetHashCode(),  Is.EqualTo(another.GetHashCode()));
                Assert.That(one.CompareTo(another),  Is.EqualTo(0));
                Assert.That(one.Equals(null),   Is.False);
            });

        }

        #endregion

    }

}
