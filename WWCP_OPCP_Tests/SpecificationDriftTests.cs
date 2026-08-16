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

using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests
{

    /// <summary>
    /// OPCP ships without a changelog and without git tags: an updated submodule pointer is
    /// the only signal that the specification moved, and nothing about it is loud. These tests
    /// turn that signal into a failing build, naming the document that changed, so that the
    /// implementation is re-read against the new text rather than silently drifting from it.
    /// </summary>
    [TestFixture]
    public class SpecificationDriftTests
    {

        #region The_implemented_release_is_the_only_one_published()

        /// <summary>
        /// A second release directory means a new OPCP release exists that this library
        /// has never been compared against.
        /// </summary>
        [Test]
        public void The_implemented_release_is_the_only_one_published()
        {

            SpecificationRepository.IgnoreWhenUnavailable();

            var releases = SpecificationRepository.ReleaseDirectories.Select(directory => directory.Name).Order().ToArray();

            Assert.That(releases,
                        Is.EqualTo(new[] { $"OPCP-{OPCPSpecification.Release}" }),
                        $"The specification publishes the releases [{releases.AggregateWith(", ")}], " +
                        $"but this library implements '{OPCPSpecification.Release}'.");

        }

        #endregion

        #region Document_versions_match_the_implemented_specification(FileName, ExpectedVersion)

        /// <summary>
        /// Every OPCP interface document carries its own 'info.version', and they advance
        /// independently of the release as a whole.
        /// </summary>
        [TestCase("accessToken.v1.json",     OPCPSpecification.DocumentVersions.AccessToken)]
        [TestCase("rcp.v1.json",             OPCPSpecification.DocumentVersions.RCP)]
        [TestCase("pcp.v1.json",             OPCPSpecification.DocumentVersions.PCP)]
        [TestCase("cps.v1.json",             OPCPSpecification.DocumentVersions.CPS)]
        [TestCase("ccp.v1.json",             OPCPSpecification.DocumentVersions.CCP)]
        [TestCase("est.v1.json",             OPCPSpecification.DocumentVersions.EST)]
        [TestCase("webhooks.v1.json",        OPCPSpecification.DocumentVersions.Webhooks)]
        [TestCase("webhook.payload.v1.json", OPCPSpecification.DocumentVersions.WebhookPayload)]
        public void Document_versions_match_the_implemented_specification(String FileName, String ExpectedVersion)
        {

            SpecificationRepository.IgnoreWhenUnavailable();

            var document = SpecificationRepository.ReadDocument(FileName);

            Assert.Multiple(() => {

                Assert.That(document.Value<String>("openapi"),
                            Is.EqualTo(OPCPSpecification.OpenAPIVersion),
                            $"'{FileName}' is no longer OpenAPI {OPCPSpecification.OpenAPIVersion}.");

                Assert.That((document["info"] as JObject)?.Value<String>("version"),
                            Is.EqualTo(ExpectedVersion),
                            $"'{FileName}' changed its version: re-read it before bumping " +
                            $"{nameof(OPCPSpecification)}.{nameof(OPCPSpecification.DocumentVersions)}.");

            });

        }

        #endregion

        #region Every_published_document_is_implemented()

        /// <summary>
        /// A document that appears in the specification without appearing here is an
        /// interface nobody has looked at yet.
        /// </summary>
        [Test]
        public void Every_published_document_is_implemented()
        {

            SpecificationRepository.IgnoreWhenUnavailable();

            var published = SpecificationRepository.ReferenceDirectory!.
                                GetFiles("*.json").
                                Select(file => file.Name).
                                Order().
                                ToArray();

            Assert.That(published,
                        Is.EqualTo(new[] {
                            "accessToken.v1.json",
                            "ccp.v1.json",
                            "cps.v1.json",
                            "est.v1.json",
                            "pcp.v1.json",
                            "rcp.v1.json",
                            "webhook.payload.v1.json",
                            "webhooks.v1.json"
                        }),
                        $"The specification now publishes [{published.AggregateWith(", ")}].");

        }

        #endregion

    }

}
