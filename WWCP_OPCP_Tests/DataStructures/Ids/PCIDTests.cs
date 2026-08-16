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
    /// A PCID identifies one vehicle, and unlike an EMAID it is not normalized: it is the Common
    /// Name of the vehicle's provisioning certificate, so the spelling that arrives is the spelling
    /// that is kept. Comparison is case-insensitive all the same, so a lookup does not depend on
    /// which spelling was stored first.
    /// </summary>
    [TestFixture]
    public class PCIDTests
    {

        #region Well_formed_PCIDs_are_accepted(Text, ExpectedLength)

        /// <summary>
        /// 'WMI123456712345678' is the PCID of the worked examples throughout pcp.v1.json.
        /// </summary>
        [TestCase("WMI123456712345678",  18UL, Description = "the specification's own example, with check digit")]
        [TestCase("WMI12345671234567",   17UL, Description = "without check digit")]
        [TestCase("wmi12345671234567",   17UL, Description = "lowercase is permitted by the pattern")]
        [TestCase("000000000000000000",  18UL, Description = "all digits")]
        public void Well_formed_PCIDs_are_accepted(String Text, UInt64 ExpectedLength)
        {

            Assert.That(PCID.TryParse(Text, out var pcid),  Is.True);

            Assert.Multiple(() => {
                Assert.That(pcid.ToString(),  Is.EqualTo(Text), "A PCID must be kept exactly as given.");
                Assert.That(pcid.Length,      Is.EqualTo(ExpectedLength));
            });

        }

        #endregion

        #region Malformed_PCIDs_are_rejected(Text)

        [TestCase("",                       Description = "empty")]
        [TestCase("WMI1234567123456",       Description = "16 characters, one too few")]
        [TestCase("WMI1234567123456789",    Description = "19 characters, one too many")]
        [TestCase("WMI-123456712345678",    Description = "hyphens are not part of a PCID")]
        [TestCase("WMI 12345671234567",     Description = "space")]
        [TestCase("WMI_12345671234567",     Description = "underscore")]
        public void Malformed_PCIDs_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(PCID.TryParse(Text, out _),  Is.False);
                Assert.That(PCID.TryParse(Text),         Is.Null);
                Assert.That(() => PCID.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region The_parts_of_a_PCID_are_addressable()

        [Test]
        public void The_parts_of_a_PCID_are_addressable()
        {

            var withCheckDigit     = PCID.Parse("WMI123456712345678");
            var withoutCheckDigit  = PCID.Parse("WMI12345671234567");

            Assert.Multiple(() => {

                Assert.That(withCheckDigit.WMI.ToString(),     Is.EqualTo("WMI"));
                Assert.That(withCheckDigit.VehicleId,          Is.EqualTo("12345671234567"));
                Assert.That(withCheckDigit.CheckDigit,         Is.EqualTo('8'));

                Assert.That(withoutCheckDigit.WMI.ToString(),  Is.EqualTo("WMI"));
                Assert.That(withoutCheckDigit.VehicleId,       Is.EqualTo("12345671234567"));
                Assert.That(withoutCheckDigit.CheckDigit,      Is.Null);

            });

        }

        #endregion

        #region The_manufacturer_prefix_survives_a_change_of_case()

        /// <summary>
        /// The WMI decides who may write this vehicle's provisioning certificate. Since a PCID keeps
        /// whatever case it arrived in, the WMI derived from it must not: 'wmi...' and 'WMI...' are
        /// the same manufacturer, and an authorization check that disagreed would be a hole.
        /// </summary>
        [Test]
        public void The_manufacturer_prefix_survives_a_change_of_case()
        {

            var granted = WMI.Parse("WMI");

            Assert.Multiple(() => {
                Assert.That(PCID.Parse("WMI123456712345678").WMI,  Is.EqualTo(granted));
                Assert.That(PCID.Parse("wmi123456712345678").WMI,  Is.EqualTo(granted));
                Assert.That(PCID.Parse("XYZ123456712345678").WMI,  Is.Not.EqualTo(granted));
            });

        }

        #endregion

        #region Case_differences_do_not_make_two_PCIDs()

        /// <summary>
        /// Case is preserved but never distinguishing - including in a dictionary, which is how the
        /// pools index their vehicles.
        /// </summary>
        [Test]
        public void Case_differences_do_not_make_two_PCIDs()
        {

            var upper  = PCID.Parse("WMI123456712345678");
            var lower  = PCID.Parse("wmi123456712345678");

            var pools  = new Dictionary<PCID, String> {
                             { upper, "stored under the uppercase spelling" }
                         };

            Assert.Multiple(() => {
                Assert.That(upper,                        Is.EqualTo(lower));
                Assert.That(upper.GetHashCode(),          Is.EqualTo(lower.GetHashCode()));
                Assert.That(pools.ContainsKey(lower),     Is.True);
                Assert.That(upper.ToString(),             Is.Not.EqualTo(lower.ToString()));
            });

        }

        #endregion

        #region Random_PCIDs_round_trip(WithCheckDigit)

        [TestCase(false)]
        [TestCase(true)]
        public void Random_PCIDs_round_trip(Boolean WithCheckDigit)
        {

            var wmi = WMI.Parse("ECD");

            for (var i = 0; i < 250; i++)
            {

                var pcid = PCID.NewRandom(wmi, WithCheckDigit);

                Assert.Multiple(() => {
                    Assert.That(PCID.TryParse(pcid.ToString(), out var reparsed) && reparsed == pcid,  Is.True, $"'{pcid}' did not round-trip.");
                    Assert.That(pcid.WMI,     Is.EqualTo(wmi));
                    Assert.That(pcid.Length,  Is.EqualTo(WithCheckDigit ? 18UL : 17UL));
                });

            }

        }

        #endregion

        #region An_empty_PCID_has_no_parts()

        [Test]
        public void An_empty_PCID_has_no_parts()
        {

            var empty = default(PCID);

            Assert.Multiple(() => {
                Assert.That(empty.IsNullOrEmpty,      Is.True);
                Assert.That(empty.ToString(),         Is.Empty);
                Assert.That(empty.WMI.IsNullOrEmpty,  Is.True);
                Assert.That(empty.VehicleId,          Is.Empty);
                Assert.That(empty.CheckDigit,         Is.Null);
            });

        }

        #endregion

    }

}
