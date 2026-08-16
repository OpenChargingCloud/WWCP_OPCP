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
    /// The two prefixes an OPCP access token is scoped by: a vehicle manufacturer is granted
    /// World Manufacturer Identifiers, an e-mobility provider is granted provider identifications.
    /// Both are normalized to uppercase, because they are compared against a granted list and a
    /// comparison that depended on spelling would be a hole rather than a nuisance.
    /// </summary>
    [TestFixture]
    public class AuthorizationScopeIdTests
    {

        #region WMIs_are_normalized_to_uppercase(Text, Expected)

        /// <summary>
        /// 'ECD' is the value of the pcid claim in the specification's own example token.
        /// </summary>
        [TestCase("ECD",  "ECD")]
        [TestCase("ecd",  "ECD")]
        [TestCase("eCd",  "ECD")]
        [TestCase("1A2",  "1A2")]
        [TestCase(" ECD ", "ECD")]
        public void WMIs_are_normalized_to_uppercase(String Text, String Expected)
        {

            Assert.That(WMI.TryParse(Text, out var wmi),  Is.True);

            Assert.Multiple(() => {
                Assert.That(wmi.ToString(),  Is.EqualTo(Expected));
                Assert.That(wmi.Length,      Is.EqualTo(3UL));
            });

        }

        #endregion

        #region Malformed_WMIs_are_rejected(Text)

        [TestCase("",      Description = "empty")]
        [TestCase("EC",    Description = "two characters")]
        [TestCase("ECDX",  Description = "four characters")]
        [TestCase("EC-",   Description = "hyphen")]
        [TestCase("EC_",   Description = "underscore")]
        public void Malformed_WMIs_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(WMI.TryParse(Text, out _),  Is.False);
                Assert.That(WMI.TryParse(Text),         Is.Null);
                Assert.That(() => WMI.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region Provider_identifications_are_normalized(Text, Expected)

        /// <summary>
        /// 'DEECD' is the value of the emaid claim in the specification's own example token.
        /// The hyphenated spelling is what a human writes; both mean one provider.
        /// </summary>
        [TestCase("DEECD",   "DEECD")]
        [TestCase("DE-ECD",  "DEECD")]
        [TestCase("de-ecd",  "DEECD")]
        [TestCase("deecd",   "DEECD")]
        public void Provider_identifications_are_normalized(String Text, String Expected)
        {

            Assert.That(Provider_Id.TryParse(Text, out var providerId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(providerId.ToString(),    Is.EqualTo(Expected));
                Assert.That(providerId.CountryCode,   Is.EqualTo("DE"));
                Assert.That(providerId.ProviderCode,  Is.EqualTo("ECD"));
                Assert.That(providerId.Length,        Is.EqualTo(5UL));
            });

        }

        #endregion

        #region Malformed_provider_identifications_are_rejected(Text)

        [TestCase("",        Description = "empty")]
        [TestCase("DEEC",    Description = "four characters")]
        [TestCase("DEECDX",  Description = "six characters")]
        [TestCase("D1ECD",   Description = "digit in the country code")]
        [TestCase("12ECD",   Description = "digits instead of a country code")]
        [TestCase("DE ECD",  Description = "space")]
        public void Malformed_provider_identifications_are_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(Provider_Id.TryParse(Text, out _),  Is.False);
                Assert.That(Provider_Id.TryParse(Text),         Is.Null);
                Assert.That(() => Provider_Id.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region Random_scopes_round_trip()

        [Test]
        public void Random_scopes_round_trip()
        {

            for (var i = 0; i < 250; i++)
            {

                var wmi         = WMI.NewRandom();
                var providerId  = Provider_Id.NewRandom();

                Assert.Multiple(() => {
                    Assert.That(WMI.        TryParse(wmi.       ToString(), out var reparsedWMI)      && reparsedWMI      == wmi,         Is.True, $"'{wmi}' did not round-trip.");
                    Assert.That(Provider_Id.TryParse(providerId.ToString(), out var reparsedProvider) && reparsedProvider == providerId,  Is.True, $"'{providerId}' did not round-trip.");
                });

            }

        }

        #endregion

        #region Empty_scopes_are_inspectable()

        [Test]
        public void Empty_scopes_are_inspectable()
        {

            Assert.Multiple(() => {

                Assert.That(default(WMI).IsNullOrEmpty,             Is.True);
                Assert.That(default(WMI).ToString(),                Is.Empty);

                Assert.That(default(Provider_Id).IsNullOrEmpty,     Is.True);
                Assert.That(default(Provider_Id).ToString(),        Is.Empty);
                Assert.That(default(Provider_Id).CountryCode,       Is.Empty);
                Assert.That(default(Provider_Id).ProviderCode,      Is.Empty);

            });

        }

        #endregion

    }

}
