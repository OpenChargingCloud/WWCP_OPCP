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

namespace cloud.charging.open.protocols.opcp.Tests.DataStructures.Ids
{

    /// <summary>
    /// EMAIDs arrive in whichever of ISO 15118-2's written forms the sender preferred, and OPCP
    /// resolves that by normalizing. What matters is that every form of one contract identifier
    /// becomes the same value here - otherwise a contract stored under one spelling could not be
    /// found under another.
    /// </summary>
    [TestFixture]
    public class EMAIdTests
    {

        #region Normalized_EMAIDs_are_accepted(Text)

        /// <summary>
        /// 'EMP99CQAPAB004' is the EMAID of the worked example in ccp.v1.json, and the Common Name
        /// of the contract certificate inside that example's response.
        /// </summary>
        [TestCase("EMP99CQAPAB004")]
        [TestCase("DEECD123456789")]
        [TestCase("DE000000000000")]
        public void Normalized_EMAIDs_are_accepted(String Text)
        {

            Assert.That(EMA_Id.TryParse(Text, out var emaId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(emaId.ToString(),  Is.EqualTo(Text));
                Assert.That(emaId.Length,      Is.EqualTo(14UL));
                Assert.That(emaId.CheckDigit,  Is.Null);
            });

        }

        #endregion

        #region Every_written_form_becomes_the_same_EMAID(Text)

        /// <summary>
        /// Hyphens are dropped and letters uppercased, so the four ways of writing one EMAID are
        /// one value. The fourth is the mixed-separator form: the narrative specification's regex
        /// requires the separators to be consistent, while the pattern the APIs actually validate
        /// against does not, and the more permissive of the two is what arrives in practice.
        /// </summary>
        [TestCase("DEECD123456789")]
        [TestCase("DE-ECD-123456789")]
        [TestCase("de-ecd-123456789")]
        [TestCase("DE-ECD123456789")]
        public void Every_written_form_becomes_the_same_EMAID(String Text)
        {

            Assert.That(EMA_Id.TryParse(Text, out var emaId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(emaId.ToString(),  Is.EqualTo("DEECD123456789"));
                Assert.That(emaId,             Is.EqualTo(EMA_Id.Parse("DEECD123456789")));
            });

        }

        #endregion

        #region A_check_digit_is_preserved_when_given(Text)

        /// <summary>
        /// The check digit is optional and carried along untouched. It is never verified: OPCP
        /// nowhere asks for that, and the ecosystem's own normalization drops it from the
        /// 14-character form.
        /// </summary>
        [TestCase("DEECD123456789X",     "DEECD123456789X")]
        [TestCase("DE-ECD-123456789-X",  "DEECD123456789X")]
        [TestCase("de-ecd-123456789-7",  "DEECD1234567897")]
        public void A_check_digit_is_preserved_when_given(String Text, String Expected)
        {

            Assert.That(EMA_Id.TryParse(Text, out var emaId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(emaId.ToString(),  Is.EqualTo(Expected));
                Assert.That(emaId.Length,      Is.EqualTo(15UL));
                Assert.That(emaId.CheckDigit,  Is.EqualTo(Expected[14]));
            });

        }

        #endregion

        #region The_parts_of_an_EMAID_are_addressable()

        [Test]
        public void The_parts_of_an_EMAID_are_addressable()
        {

            var emaId = EMA_Id.Parse("DE-ECD-123456789-X");

            Assert.Multiple(() => {
                Assert.That(emaId.CountryCode,            Is.EqualTo("DE"));
                Assert.That(emaId.ProviderCode,           Is.EqualTo("ECD"));
                Assert.That(emaId.InstanceId,             Is.EqualTo("123456789"));
                Assert.That(emaId.CheckDigit,             Is.EqualTo('X'));
                Assert.That(emaId.ProviderId.ToString(),  Is.EqualTo("DEECD"));
            });

        }

        #endregion

        #region The_provider_prefix_is_what_an_operator_is_authorized_for()

        /// <summary>
        /// 'DEECD' is the value of the emaid claim in the specification's own example token: the
        /// prefix decides which contracts an e-mobility provider may touch, so it has to survive
        /// normalization identically whichever form the EMAID arrived in.
        /// </summary>
        [Test]
        public void The_provider_prefix_is_what_an_operator_is_authorized_for()
        {

            var granted = Provider_Id.Parse("DEECD");

            Assert.Multiple(() => {
                Assert.That(EMA_Id.Parse("DE-ECD-123456789").ProviderId,  Is.EqualTo(granted));
                Assert.That(EMA_Id.Parse("deecd123456789").  ProviderId,  Is.EqualTo(granted));
                Assert.That(EMA_Id.Parse("DEXYZ123456789").  ProviderId,  Is.Not.EqualTo(granted));
            });

        }

        #endregion

        #region Malformed_EMAIDs_are_rejected(Text)

        /// <summary>
        /// The underscore case is a deliberate deviation: the pattern the APIs validate against
        /// writes the groups as \w, which admits underscores, while the normalization rule in the
        /// narrative specification is strictly alphanumeric. An underscore in an EMAID is nothing
        /// ISO 15118 can carry, so the stricter of the two rules wins.
        /// </summary>
        [TestCase("",                    Description = "empty")]
        [TestCase("DEECD12345678",       Description = "13 characters, one too few")]
        [TestCase("DEECD1234567890X",    Description = "16 characters, one too many")]
        [TestCase("D1ECD123456789",      Description = "digit in the country code")]
        [TestCase("DEECD 123456789",     Description = "space instead of a hyphen")]
        [TestCase("DE*ECD*123456789",    Description = "asterisk separator - EVSEIDs use it, EMAIDs do not")]
        [TestCase("DE_ECD_123456789",    Description = "underscore, admitted by the JSON pattern but not by the rule")]
        [TestCase("DEECD12345678Ä",      Description = "non-ASCII")]
        public void Malformed_EMAIDs_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(EMA_Id.TryParse(Text, out _),             Is.False);
                Assert.That(EMA_Id.TryParse(Text),                    Is.Null);
                Assert.That(() => EMA_Id.Parse(Text),                 Throws.ArgumentException);
            });

        }

        #endregion

        #region Surrounding_whitespace_is_ignored()

        [Test]
        public void Surrounding_whitespace_is_ignored()
        {

            Assert.That(EMA_Id.Parse("  DEECD123456789  "),
                        Is.EqualTo(EMA_Id.Parse("DEECD123456789")));

        }

        #endregion

        #region Random_EMAIDs_round_trip(WithCheckDigit)

        [TestCase(false)]
        [TestCase(true)]
        public void Random_EMAIDs_round_trip(Boolean WithCheckDigit)
        {

            var provider = Provider_Id.Parse("DEECD");

            for (var i = 0; i < 250; i++)
            {

                var emaId = EMA_Id.NewRandom(provider, WithCheckDigit);

                Assert.Multiple(() => {
                    Assert.That(EMA_Id.TryParse(emaId.ToString(), out var reparsed) && reparsed == emaId,  Is.True, $"'{emaId}' did not round-trip.");
                    Assert.That(emaId.ProviderId,  Is.EqualTo(provider));
                    Assert.That(emaId.Length,      Is.EqualTo(WithCheckDigit ? 15UL : 14UL));
                });

            }

        }

        #endregion

        #region Equality_ignores_case_and_an_empty_EMAID_has_no_parts()

        [Test]
        public void Equality_ignores_case_and_an_empty_EMAID_has_no_parts()
        {

            var emaId = EMA_Id.Parse("DEECD123456789");
            var empty = default(EMA_Id);

            Assert.Multiple(() => {

                Assert.That(emaId.Equals(EMA_Id.Parse("deecd123456789")),  Is.True);
                Assert.That(emaId.GetHashCode(),                           Is.EqualTo(EMA_Id.Parse("deecd123456789").GetHashCode()));
                Assert.That(emaId != EMA_Id.Parse("DEECD123456780"),       Is.True);
                Assert.That(emaId.CompareTo(EMA_Id.Parse("DEECD223456789")) < 0,  Is.True);

                // A default value must be inspectable rather than explosive.
                Assert.That(empty.IsNullOrEmpty,      Is.True);
                Assert.That(empty.ToString(),         Is.Empty);
                Assert.That(empty.CountryCode,        Is.Empty);
                Assert.That(empty.ProviderId.IsNullOrEmpty,  Is.True);
                Assert.That(empty.CheckDigit,         Is.Null);

            });

        }

        #endregion

    }

}
