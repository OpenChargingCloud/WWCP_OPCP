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

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.DataStructures
{

    /// <summary>
    /// The one error shape every OPCP service uses - and that three of them reach into the
    /// certificate provisioning service's document to borrow.
    /// </summary>
    [TestFixture]
    public class OPCPErrorTests
    {

        #region An_error_as_the_specification_prints_it_is_parsed()

        /// <summary>
        /// Taken from the "Invalid EMAID" example of ccp.v1.json.
        /// </summary>
        [Test]
        public void An_error_as_the_specification_prints_it_is_parsed()
        {

            var json = JObject.Parse("""
                                     {
                                       "errorMessages": [ "emaid : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"" ],
                                       "traceId":       "b1b86334-7c74-4ccc-b78d-d4f773d3b559"
                                     }
                                     """);

            Assert.That(OPCPError.TryParse(json, out var error, out var errorResponse),  Is.True, errorResponse);

            Assert.Multiple(() => {
                Assert.That(error!.ErrorMessages.Count(),  Is.EqualTo(1));
                Assert.That(error.FirstMessage,            Does.StartWith("emaid : must match"));
                Assert.That(error.TraceId?.ToString(),     Is.EqualTo("b1b86334-7c74-4ccc-b78d-d4f773d3b559"));
            });

        }

        #endregion

        #region An_error_round_trips_through_JSON()

        [Test]
        public void An_error_round_trips_through_JSON()
        {

            var error = new OPCPError(
                            [ "The contract for the given EMAID not found.",
                              "Invalid Tupple - EMAID is already used by other PCID." ],
                            Trace_Id.NewRandom()
                        );

            Assert.That(OPCPError.TryParse(error.ToJSON(), out var parsed, out var errorResponse),  Is.True, errorResponse);
            Assert.That(parsed,  Is.EqualTo(error));

        }

        #endregion

        #region Neither_property_is_required()

        /// <summary>
        /// The schema marks nothing as required, so an empty object is a valid - if unhelpful -
        /// error. Refusing to parse it would turn a vague answer into no answer at all.
        /// </summary>
        [Test]
        public void Neither_property_is_required()
        {

            Assert.That(OPCPError.TryParse([], out var error, out var errorResponse),  Is.True, errorResponse);

            Assert.Multiple(() => {
                Assert.That(error!.ErrorMessages,  Is.Empty);
                Assert.That(error.TraceId,         Is.Null);
                Assert.That(error.FirstMessage,    Is.Empty);
                Assert.That(error.ToJSON(),        Has.Count.EqualTo(0), "Nothing to say, nothing emitted.");
                Assert.That(error.ToString(),      Is.EqualTo("An unspecified OPCP error"));
            });

        }

        #endregion

        #region Blank_and_duplicate_messages_are_dropped()

        /// <summary>
        /// The schema declares the list unique; an empty string is not a message.
        /// </summary>
        [Test]
        public void Blank_and_duplicate_messages_are_dropped()
        {

            var error = new OPCPError([ "Contract or Vehicle not found.",
                                        "Contract or Vehicle not found.",
                                        "",
                                        "   " ]);

            Assert.That(error.ErrorMessages,  Has.Exactly(1).Items);

        }

        #endregion

        #region Create_gives_every_error_a_trace_to_quote()

        [Test]
        public void Create_gives_every_error_a_trace_to_quote()
        {

            var error = OPCPError.Create("EXI format is invalid!");

            Assert.Multiple(() => {
                Assert.That(error.FirstMessage,  Is.EqualTo("EXI format is invalid!"));
                Assert.That(error.TraceId,       Is.Not.Null);
                Assert.That(error.ToString(),    Does.StartWith("EXI format is invalid! (trace "));
            });

        }

        #endregion

        #region Errors_differing_only_in_message_order_are_equal()

        [Test]
        public void Errors_differing_only_in_message_order_are_equal()
        {

            var traceId  = Trace_Id.NewRandom();
            var one      = new OPCPError([ "first", "second" ], traceId);
            var another  = new OPCPError([ "second", "first" ], traceId);

            Assert.Multiple(() => {
                Assert.That(one,             Is.EqualTo(another));
                Assert.That(one == another,  Is.True);
                Assert.That(one.Clone(),     Is.EqualTo(one));
                Assert.That(one,             Is.Not.EqualTo(new OPCPError([ "first" ], traceId)));
                Assert.That(one,             Is.Not.EqualTo(new OPCPError([ "first", "second" ], Trace_Id.NewRandom())));
            });

        }

        #endregion

    }

}
