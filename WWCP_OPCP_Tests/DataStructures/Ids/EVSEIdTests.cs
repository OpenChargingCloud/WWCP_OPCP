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
    /// An EVSE identification names one power outlet, and it is the common name of the charging
    /// station certificate a vehicle checks during the TLS handshake - so, like a PCID, it is kept
    /// exactly as it arrived.
    /// </summary>
    [TestFixture]
    public class EVSEIdTests
    {

        #region Well_formed_EVSE_identifications_are_accepted(Text)

        /// <summary>
        /// 'DE*ICE*E45B*78C' is the worked example of the identifier document.
        /// </summary>
        [TestCase("DE*ICE*E45B*78C",  Description = "the specification's own example")]
        [TestCase("DE-ICE-E45B78C",   Description = "hyphens, as the neighbouring SECCID example writes them")]
        [TestCase("DEICEE45B78C",     Description = "no separators at all")]
        [TestCase("de*ice*e45b*78c",  Description = "lowercase")]
        [TestCase("DE*ICE*E1",        Description = "the shortest power outlet the pattern allows")]
        public void Well_formed_EVSE_identifications_are_accepted(String Text)
        {

            Assert.That(EVSE_Id.TryParse(Text, out var evseId),  Is.True);

            Assert.That(evseId.ToString(),  Is.EqualTo(Text),
                        "An EVSE identification must be kept exactly as given.");

        }

        #endregion

        #region Malformed_EVSE_identifications_are_rejected(Text)

        [TestCase("",                    Description = "empty")]
        [TestCase("DE*ICE*45B*78C",      Description = "no 'E' marking it as an EVSE")]
        [TestCase("D*ICE*E45B",          Description = "a one character country code")]
        [TestCase("DE*IC*E45B",          Description = "a two character operator")]
        [TestCase("DE*ICE*E",            Description = "no power outlet")]
        [TestCase("DE*ICE*E45_B",        Description = "an underscore, which the narrative rule excludes")]
        [TestCase("DE ICE E45B",         Description = "spaces")]
        public void Malformed_EVSE_identifications_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(EVSE_Id.TryParse(Text, out _),  Is.False);
                Assert.That(EVSE_Id.TryParse(Text),         Is.Null);
                Assert.That(() => EVSE_Id.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region The_parts_of_an_EVSE_identification_are_addressable()

        [Test]
        public void The_parts_of_an_EVSE_identification_are_addressable()
        {

            var evseId = EVSE_Id.Parse("DE*ICE*E45B*78C");

            Assert.Multiple(() => {
                Assert.That(evseId.CountryCode,    Is.EqualTo("DE"));
                Assert.That(evseId.OperatorId,     Is.EqualTo("ICE"));
                Assert.That(evseId.PowerOutletId,  Is.EqualTo("45B*78C"));
            });

        }

        #endregion

        #region Comparison_ignores_case_but_not_separators()

        /// <summary>
        /// Two spellings of the same station are the same identification only if they are written
        /// the same way apart from case: nothing in the specification says an ecosystem may drop
        /// the separators of an EVSE identification, and dropping them would change a certificate
        /// subject.
        /// </summary>
        [Test]
        public void Comparison_ignores_case_but_not_separators()
        {

            Assert.Multiple(() => {

                Assert.That(EVSE_Id.Parse("DE*ICE*E45B*78C"),
                            Is.EqualTo(EVSE_Id.Parse("de*ice*e45b*78c")));

                Assert.That(EVSE_Id.Parse("DE*ICE*E45B*78C"),
                            Is.Not.EqualTo(EVSE_Id.Parse("DEICEE45B78C")));

            });

        }

        #endregion

    }

}
