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
    /// A SECC identification names the communication controller of a charging station rather than
    /// one of its outlets, which is what ISO 15118-20 puts in the certificate where ISO 15118-2
    /// puts an EVSE identification.
    /// </summary>
    [TestFixture]
    public class SECCIdTests
    {

        #region Well_formed_SECC_identifications_are_accepted(Text)

        /// <summary>
        /// 'DE-ICE-S-00003C4D557878675645330967543476-2' is the worked example of the identifier
        /// document.
        /// </summary>
        [TestCase("DE-ICE-S-00003C4D557878675645330967543476-2",  Description = "the specification's own example")]
        [TestCase("DE-ICE-S-00003C4D557878675645330967543476",    Description = "without a check digit")]
        [TestCase("DE*ICE*S*00003C4D*2",                          Description = "asterisks, as an EVSEID writes them")]
        [TestCase("DEICES00003C4D",                               Description = "no separators at all")]
        [TestCase("de-ice-s-00003c4d-2",                          Description = "lowercase")]
        public void Well_formed_SECC_identifications_are_accepted(String Text)
        {

            Assert.That(SECC_Id.TryParse(Text, out var seccId),  Is.True);

            Assert.That(seccId.ToString(),  Is.EqualTo(Text),
                        "A SECC identification must be kept exactly as given.");

        }

        #endregion

        #region Malformed_SECC_identifications_are_rejected(Text)

        [TestCase("",                    Description = "empty")]
        [TestCase("DE-ICE-E-00003C4D",   Description = "an 'E', which makes it an EVSE identification")]
        [TestCase("DE-ICE-S",            Description = "no controller")]
        [TestCase("D-ICE-S-00003C4D",    Description = "a one character country code")]
        [TestCase("DE-ICE-S-0000_3C4D",  Description = "an underscore")]
        public void Malformed_SECC_identifications_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(SECC_Id.TryParse(Text, out _),  Is.False);
                Assert.That(SECC_Id.TryParse(Text),         Is.Null);
                Assert.That(() => SECC_Id.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region The_parts_of_a_SECC_identification_are_addressable()

        [Test]
        public void The_parts_of_a_SECC_identification_are_addressable()
        {

            var seccId = SECC_Id.Parse("DE-ICE-S-00003C4D557878675645330967543476-2");

            Assert.Multiple(() => {
                Assert.That(seccId.CountryCode,   Is.EqualTo("DE"));
                Assert.That(seccId.OperatorId,    Is.EqualTo("ICE"));
                Assert.That(seccId.ControllerId,  Is.EqualTo("00003C4D557878675645330967543476"));
                Assert.That(seccId.CheckDigit,    Is.EqualTo('2'));
            });

        }

        #endregion

        #region A_check_digit_is_only_read_where_a_separator_announces_it()

        /// <summary>
        /// Without a separator nothing distinguishes a trailing check digit from the last
        /// character of the controller identification, and guessing would silently shorten the
        /// identification of a real box in a real charging station.
        /// </summary>
        [Test]
        public void A_check_digit_is_only_read_where_a_separator_announces_it()
        {

            var withSeparator     = SECC_Id.Parse("DE-ICE-S-00003C4D-2");
            var withoutSeparator  = SECC_Id.Parse("DEICES00003C4D2");

            Assert.Multiple(() => {

                Assert.That(withSeparator.ControllerId,     Is.EqualTo("00003C4D"));
                Assert.That(withSeparator.CheckDigit,       Is.EqualTo('2'));

                Assert.That(withoutSeparator.ControllerId,  Is.EqualTo("00003C4D2"));
                Assert.That(withoutSeparator.CheckDigit,    Is.Null);

            });

        }

        #endregion

    }

}
