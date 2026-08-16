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

namespace cloud.charging.open.protocols.opcp.Tests.DataStructures
{

    /// <summary>
    /// OPCP's closed-ish vocabularies. They are modelled as predefined strings rather than as
    /// enumerations for two reasons: the specification spells several of them inconsistently and
    /// both spellings have to mean one value, and an ecosystem is allowed to grow a word this
    /// library has never heard without every response it appears in becoming unreadable.
    /// </summary>
    [TestFixture]
    public class VocabularyTests
    {

        #region Root_certificate_types_survive_the_specifications_two_spellings(Text)

        /// <summary>
        /// getAllRootCerts filters on 'mo', 'v2g' and 'oem'; the certificates it returns carry
        /// 'MO', 'V2G' and 'OEM'. One value either way, emitted uppercase.
        /// </summary>
        [TestCase("V2G",  "V2G")]
        [TestCase("v2g",  "V2G")]
        [TestCase("mo",   "MO")]
        [TestCase("MO",   "MO")]
        [TestCase("oem",  "OEM")]
        [TestCase("PE",   "PE")]
        public void Root_certificate_types_survive_the_specifications_two_spellings(String Text, String Expected)
        {

            Assert.That(RootCertificateType.TryParse(Text, out var rootCertificateType),  Is.True);
            Assert.That(rootCertificateType.ToString(),  Is.EqualTo(Expected));

        }

        #endregion

        #region The_four_root_certificate_types_are_registered()

        [Test]
        public void The_four_root_certificate_types_are_registered()
        {

            Assert.Multiple(() => {
                Assert.That(RootCertificateType.All,  Has.Member(RootCertificateType.MO));
                Assert.That(RootCertificateType.All,  Has.Member(RootCertificateType.V2G));
                Assert.That(RootCertificateType.All,  Has.Member(RootCertificateType.OEM));
                Assert.That(RootCertificateType.All,  Has.Member(RootCertificateType.PE));

                Assert.That(RootCertificateType.Parse("v2g"),  Is.EqualTo(RootCertificateType.V2G));
                Assert.That(RootCertificateType.V2G,           Is.Not.EqualTo(RootCertificateType.OEM));
            });

        }

        #endregion

        #region Signature_algorithms_are_the_three_ISO_15118_curves(Text, Expected)

        [TestCase("secp256r1",  "secp256r1")]
        [TestCase("SECP256R1",  "secp256r1")]
        [TestCase("secp521r1",  "secp521r1")]
        [TestCase("Ed448",      "ed448")]
        public void Signature_algorithms_are_the_three_ISO_15118_curves(String Text, String Expected)
        {

            Assert.That(SignatureAlgorithm.Parse(Text).ToString(),  Is.EqualTo(Expected));

        }

        #endregion

        #region Both_spellings_of_ISO_15118_20_mean_the_same_generation()

        /// <summary>
        /// The root certificate pool and the webhook payloads write the ISO 15118-20 namespace
        /// with 2022; the enrollment service writes it with 2020. Neither is a value this library
        /// may quietly rewrite - each is emitted where the specification asks for it - but code
        /// deciding what generation it is looking at must see one answer.
        /// </summary>
        [Test]
        public void Both_spellings_of_ISO_15118_20_mean_the_same_generation()
        {

            Assert.Multiple(() => {

                Assert.That(XSD_MsgDefNamespace.ISO15118_2.      ToString(),  Is.EqualTo("urn:iso:15118:2:2013:MsgDef"));
                Assert.That(XSD_MsgDefNamespace.ISO15118_20.     ToString(),  Is.EqualTo("urn:iso:15118:20:2022:MsgDef"));
                Assert.That(XSD_MsgDefNamespace.ISO15118_20_2020.ToString(),  Is.EqualTo("urn:iso:15118:20:2020:MsgDef"));

                Assert.That(XSD_MsgDefNamespace.ISO15118_2.      IsISO15118_2,   Is.True);
                Assert.That(XSD_MsgDefNamespace.ISO15118_2.      IsISO15118_20,  Is.False);

                Assert.That(XSD_MsgDefNamespace.ISO15118_20.     IsISO15118_20,  Is.True);
                Assert.That(XSD_MsgDefNamespace.ISO15118_20_2020.IsISO15118_20,  Is.True);
                Assert.That(XSD_MsgDefNamespace.ISO15118_20.     IsISO15118_2,   Is.False);

                // The two -20 spellings remain distinguishable, because each has to go back
                // out the way it came in.
                Assert.That(XSD_MsgDefNamespace.ISO15118_20,  Is.Not.EqualTo(XSD_MsgDefNamespace.ISO15118_20_2020));

                Assert.That(XSD_MsgDefNamespace.Parse("urn:iso:15118:2:2013:MsgDef"),
                            Is.EqualTo(XSD_MsgDefNamespace.ISO15118_2));

            });

        }

        #endregion

        #region Roles_from_the_specifications_example_token_are_understood()

        /// <summary>
        /// The example token of accessToken.v1.json carries
        /// ["CPO", "OEM", "AUDI", "MO_HUBJECT_PKI", "MO_EXTERNAL_PKI"] - four roles this library
        /// knows and one that is a particular manufacturer's own name. The unknown one has to
        /// survive, or a token would be unreadable because of a word that was never ours to define.
        /// </summary>
        [Test]
        public void Roles_from_the_specifications_example_token_are_understood()
        {

            var roles = new[] { "CPO", "OEM", "AUDI", "MO_HUBJECT_PKI", "MO_EXTERNAL_PKI" }.
                            Select(OPCPRole.Parse).
                            ToArray();

            Assert.Multiple(() => {

                Assert.That(roles,  Has.Member(OPCPRole.CPO));
                Assert.That(roles,  Has.Member(OPCPRole.OEM));
                Assert.That(roles,  Has.Member(OPCPRole.MO_V2GPKI));
                Assert.That(roles,  Has.Member(OPCPRole.MO_ExternalPKI));

                Assert.That(roles[2].ToString(),  Is.EqualTo("AUDI"), "An operator-specific role is kept as given.");

                Assert.That(OPCPRole.MO_V2GPKI.     IsMobilityOperator,  Is.True);
                Assert.That(OPCPRole.MO_ExternalPKI.IsMobilityOperator,  Is.True);
                Assert.That(OPCPRole.MO.            IsMobilityOperator,  Is.True);
                Assert.That(OPCPRole.CPO.           IsMobilityOperator,  Is.False);
                Assert.That(OPCPRole.Admin.         IsMobilityOperator,  Is.False);

                // The two kinds of mobility operator are different rights, not spellings.
                Assert.That(OPCPRole.MO_V2GPKI,  Is.Not.EqualTo(OPCPRole.MO_ExternalPKI));

            });

        }

        #endregion

        #region Empty_text_is_not_a_vocabulary_word()

        [Test]
        public void Empty_text_is_not_a_vocabulary_word()
        {

            Assert.Multiple(() => {

                Assert.That(RootCertificateType.TryParse("",   out _),  Is.False);
                Assert.That(SignatureAlgorithm. TryParse("  ", out _),  Is.False);
                Assert.That(XSD_MsgDefNamespace.TryParse("",   out _),  Is.False);
                Assert.That(OPCPRole.           TryParse("",   out _),  Is.False);

                Assert.That(() => RootCertificateType.Parse(""),  Throws.ArgumentException);
                Assert.That(() => OPCPRole.           Parse(""),  Throws.ArgumentException);

                Assert.That(default(RootCertificateType).IsNullOrEmpty,  Is.True);
                Assert.That(default(SignatureAlgorithm). IsNullOrEmpty,  Is.True);
                Assert.That(default(XSD_MsgDefNamespace).IsNullOrEmpty,  Is.True);
                Assert.That(default(OPCPRole).           IsNullOrEmpty,  Is.True);

            });

        }

        #endregion

    }

}
