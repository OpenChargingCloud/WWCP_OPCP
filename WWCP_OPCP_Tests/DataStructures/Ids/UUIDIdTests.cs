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
    /// The two identifications OPCP mints itself rather than deriving from the domain: the handle
    /// a Root Certificate Pool gives a stored root, and the trace identification that accompanies
    /// every error response. Both are UUIDs in the hyphenated form the specification's patterns
    /// describe, and both are normalized to lowercase, which is the form RFC 4122 asks for.
    /// </summary>
    [TestFixture]
    public class UUIDIdTests
    {

        #region Data

        // The rootCertificateId of the V2G Root CA G2 example in rcp.v1.json.
        private const String SpecificationExample = "b1b86334-7c74-4ccc-b78d-d4f773d3b559";

        #endregion


        #region Root_certificate_identifications_round_trip()

        [Test]
        public void Root_certificate_identifications_round_trip()
        {

            Assert.That(RootCertificate_Id.TryParse(SpecificationExample, out var rootCertificateId),  Is.True);

            Assert.Multiple(() => {
                Assert.That(rootCertificateId.ToString(),  Is.EqualTo(SpecificationExample));
                Assert.That(rootCertificateId.Length,      Is.EqualTo(36UL));
            });

        }

        #endregion

        #region Uppercase_UUIDs_are_normalized_to_lowercase()

        [Test]
        public void Uppercase_UUIDs_are_normalized_to_lowercase()
        {

            var upper = RootCertificate_Id.Parse(SpecificationExample.ToUpperInvariant());

            Assert.Multiple(() => {
                Assert.That(upper.ToString(),  Is.EqualTo(SpecificationExample));
                Assert.That(upper,             Is.EqualTo(RootCertificate_Id.Parse(SpecificationExample)));
            });

        }

        #endregion

        #region Only_the_hyphenated_form_is_accepted(Text)

        /// <summary>
        /// .NET happily parses braced, parenthesized and bare UUIDs. The specification's pattern
        /// describes the hyphenated form and nothing else, and a pool that accepted a shape it
        /// never emits would be inviting round-trip surprises.
        /// </summary>
        [TestCase("",                                        Description = "empty")]
        [TestCase("b1b863347c744cccb78dd4f773d3b559",         Description = "bare, without hyphens")]
        [TestCase("{b1b86334-7c74-4ccc-b78d-d4f773d3b559}",   Description = "braced")]
        [TestCase("(b1b86334-7c74-4ccc-b78d-d4f773d3b559)",   Description = "parenthesized")]
        [TestCase("b1b86334-7c74-4ccc-b78d-d4f773d3b55",      Description = "one character short")]
        [TestCase("not-a-uuid",                               Description = "nothing like a UUID")]
        public void Only_the_hyphenated_form_is_accepted(String Text)
        {

            Assert.Multiple(() => {

                Assert.That(RootCertificate_Id.TryParse(Text, out _),  Is.False);
                Assert.That(RootCertificate_Id.TryParse(Text),         Is.Null);
                Assert.That(() => RootCertificate_Id.Parse(Text),      Throws.ArgumentException);

                Assert.That(Trace_Id.TryParse(Text, out _),            Is.False);
                Assert.That(() => Trace_Id.Parse(Text),                Throws.ArgumentException);

            });

        }

        #endregion

        #region Random_identifications_are_distinct_and_round_trip()

        [Test]
        public void Random_identifications_are_distinct_and_round_trip()
        {

            var rootCertificateIds  = new HashSet<RootCertificate_Id>();
            var traceIds            = new HashSet<Trace_Id>();

            for (var i = 0; i < 250; i++)
            {

                var rootCertificateId  = RootCertificate_Id.NewRandom();
                var traceId            = Trace_Id.NewRandom();

                Assert.Multiple(() => {
                    Assert.That(RootCertificate_Id.TryParse(rootCertificateId.ToString(), out var reparsedRoot)  && reparsedRoot  == rootCertificateId,  Is.True);
                    Assert.That(Trace_Id.          TryParse(traceId.          ToString(), out var reparsedTrace) && reparsedTrace == traceId,            Is.True);
                });

                rootCertificateIds.Add(rootCertificateId);
                traceIds.          Add(traceId);

            }

            Assert.Multiple(() => {
                Assert.That(rootCertificateIds,  Has.Count.EqualTo(250));
                Assert.That(traceIds,            Has.Count.EqualTo(250));
            });

        }

        #endregion

        #region Empty_identifications_are_inspectable()

        [Test]
        public void Empty_identifications_are_inspectable()
        {

            Assert.Multiple(() => {
                Assert.That(default(RootCertificate_Id).IsNullOrEmpty,  Is.True);
                Assert.That(default(RootCertificate_Id).ToString(),     Is.Empty);
                Assert.That(default(Trace_Id).          IsNullOrEmpty,  Is.True);
                Assert.That(default(Trace_Id).          ToString(),     Is.Empty);
            });

        }

        #endregion

    }

}
