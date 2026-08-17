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
    /// Which authority of a V2G PKI service an enrollment request is addressed to: one of five
    /// kinds, optionally prefixed with the name of the operator running it - which is how one PKI
    /// service serves several.
    /// </summary>
    [TestFixture]
    public class CAIdTests
    {

        #region The_five_default_authorities_are_accepted(Text)

        [TestCase("cpo")]
        [TestCase("mo")]
        [TestCase("oem")]
        [TestCase("veh")]
        [TestCase("cps")]
        public void The_five_default_authorities_are_accepted(String Text)
        {

            Assert.That(CA_Id.TryParse(Text, out var caId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(caId.ToString(),      Is.EqualTo(Text));
                Assert.That(caId.Type.ToString(), Is.EqualTo(Text));
                Assert.That(caId.OperatorPrefix,  Is.Null);
            });

        }

        #endregion

        #region An_operator_may_run_an_authority_of_its_own()

        /// <summary>
        /// Both halves are kept: dropping the prefix would send an enrollment to the wrong
        /// authority, and dropping the type would lose what kind of certificate was asked for.
        /// </summary>
        [Test]
        public void An_operator_may_run_an_authority_of_its_own()
        {

            var caId = CA_Id.Parse("hubject-cpo");

            Assert.Multiple(() => {

                Assert.That(caId.ToString(),      Is.EqualTo("hubject-cpo"));
                Assert.That(caId.Type,            Is.EqualTo(CA_Type.CPO));
                Assert.That(caId.OperatorPrefix,  Is.EqualTo("hubject"));

                // A different authority from the default one of the same kind.
                Assert.That(caId,                 Is.Not.EqualTo(CA_Id.Parse(CA_Type.CPO)));

            });

        }

        #endregion

        #region Anything_that_is_not_one_of_the_five_kinds_is_rejected(Text)

        [TestCase("",              Description = "empty")]
        [TestCase("cpo2",          Description = "not one of the five")]
        [TestCase("hubject",       Description = "a prefix and no kind")]
        [TestCase("hubject-",      Description = "a prefix and nothing after it")]
        [TestCase("-cpo",          Description = "a separator and no prefix")]
        [TestCase("hub ject-cpo",  Description = "a space in the prefix")]
        public void Anything_that_is_not_one_of_the_five_kinds_is_rejected(String Text)
        {

            Assert.Multiple(() => {
                Assert.That(CA_Id.TryParse(Text, out _),  Is.False);
                Assert.That(CA_Id.TryParse(Text),         Is.Null);
                Assert.That(() => CA_Id.Parse(Text),      Throws.ArgumentException);
            });

        }

        #endregion

        #region The_two_authorities_that_certify_vehicles_say_so()

        /// <summary>
        /// The manufacturer authority and the ISO 15118-20 vehicle authority ask for the same
        /// kind of common name, which is what the enrollment service actually needs to know.
        /// </summary>
        [Test]
        public void The_two_authorities_that_certify_vehicles_say_so()
        {

            Assert.Multiple(() => {
                Assert.That(CA_Type.OEM.IssuesForVehicles,  Is.True);
                Assert.That(CA_Type.VEH.IssuesForVehicles,  Is.True);
                Assert.That(CA_Type.CPO.IssuesForVehicles,  Is.False);
                Assert.That(CA_Type.MO. IssuesForVehicles,  Is.False);
                Assert.That(CA_Type.CPS.IssuesForVehicles,  Is.False);
            });

        }

        #endregion

    }

}
