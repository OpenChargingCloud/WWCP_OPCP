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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// What a log file is allowed to contain.
    ///
    /// Every OPCP request carries a bearer token, the token endpoint's own traffic carries the
    /// credential that mints them, and a webhook registration comes back with a signing secret.
    /// Each of those in a log file is a whole credential, reusable by whoever finds it.
    /// </summary>
    [TestFixture]
    public class ClientLoggerTests : AOPCPEcosystemTests
    {

        #region The_bearer_token_never_reaches_the_log()

        [Test]
        public async Task The_bearer_token_never_reaches_the_log()
        {

            var lines   = new List<String>();
            var logger  = new OPCPClientLogger(lines.Add);

            var token   = tokenIssuer.IssueToken([ OPCPRole.OEM ], ClientName: "logged-partner").AccessToken;

            var client  = new Webhook_HTTPClient(baseURL, new StaticAccessTokenProvider(token));

            logger.Attach(client);

            var created = await client.CreateEndpoint(
                                    URL.Parse($"{baseURL}/nowhere/"),
                                    [ WebhookEventType.ContractCreated ]
                                );

            Assert.That(created.IsSuccess,  Is.True, created.Error?.ToString());

            var log = String.Join(Environment.NewLine, lines);

            Assert.Multiple(() => {

                Assert.That(lines,                    Has.Count.EqualTo(2), "one line out, one line back");
                Assert.That(logger.Exchanges,         Is.EqualTo(1));

                Assert.That(log,                      Does.Contain("POST"));
                Assert.That(log,                      Does.Contain("/v1/webhook/endpoints"));
                Assert.That(log,                      Does.Contain("201"));

                Assert.That(log,                      Does.Not.Contain(token),
                            "The whole point: a token in a log file is a token anybody can use.");

                Assert.That(log,                      Does.Contain(OPCPClientLogger.Redacted));

            });

        }

        #endregion

        #region A_secret_that_came_back_in_a_body_does_not_reach_the_log_either()

        /// <summary>
        /// Bodies are off by default and elide the known secrets even when they are on - because
        /// a webhook registration answers with the one value that lets a partner tell a real event
        /// from an invented one.
        /// </summary>
        [Test]
        public async Task A_secret_that_came_back_in_a_body_does_not_reach_the_log_either()
        {

            var lines   = new List<String>();
            var logger  = new OPCPClientLogger(lines.Add, LogBodies: true);

            var client  = new Webhook_HTTPClient(
                              baseURL,
                              new StaticAccessTokenProvider(
                                  tokenIssuer.IssueToken([ OPCPRole.OEM ], ClientName: "logged-partner").AccessToken
                              )
                          );

            logger.Attach(client);

            var created = await client.CreateEndpoint(
                                    URL.Parse($"{baseURL}/nowhere/"),
                                    [ WebhookEventType.ContractCreated ]
                                );

            Assert.That(created.IsSuccess,  Is.True, created.Error?.ToString());

            var log = String.Join(Environment.NewLine, lines);

            Assert.Multiple(() => {

                // The body did get written, which is what LogBodies is for...
                Assert.That(log,  Does.Contain("enabledEvents"));

                // ...but not the one field in it that is a credential.
                Assert.That(log,  Does.Not.Contain(created.Data!.Secret!));

            });

        }

        #endregion

        #region A_detached_logger_stops_listening()

        [Test]
        public async Task A_detached_logger_stops_listening()
        {

            var lines   = new List<String>();
            var logger  = new OPCPClientLogger(lines.Add);

            var client  = new RCP_HTTPClient(baseURL, TokenFor(OPCPRole.Admin));

            logger.Attach(client);
            await client.GetAllRootCerts();

            logger.Detach(client);
            await client.GetAllRootCerts();

            Assert.That(lines,  Has.Count.EqualTo(2), "Only the first exchange was written down.");

        }

        #endregion

        #region Redaction_works_on_what_it_was_written_for()

        [Test]
        public void Redaction_works_on_what_it_was_written_for()
        {

            Assert.Multiple(() => {

                Assert.That(OPCPClientLogger.Redact("Authorization: Bearer eyJhbGciOi.aaa.bbb"),
                            Is.EqualTo($"Authorization: Bearer {OPCPClientLogger.Redacted}"));

                Assert.That(OPCPClientLogger.Redact("authorization: Basic dXNlcjpwYXNz"),
                            Is.EqualTo($"authorization: Basic {OPCPClientLogger.Redacted}"));

                Assert.That(OPCPClientLogger.Redact("{\"secret\":\"abc123\",\"url\":\"https://x/y\"}"),
                            Does.Not.Contain("abc123").And.Contain("https://x/y"));

                Assert.That(OPCPClientLogger.Redact("{\"access_token\":\"eyJ...\",\"expires_in\":86400}"),
                            Does.Not.Contain("eyJ...").And.Contain("86400"));

                Assert.That(OPCPClientLogger.Redact("grant_type=client_credentials&client_secret=hunter2"),
                            Does.Not.Contain("hunter2").And.Contain("grant_type=client_credentials"));

                // Nothing that is not a credential is touched: a log that hides what went wrong
                // is no better than no log.
                Assert.That(OPCPClientLogger.Redact("{\"emaid\":\"DEECD123456789\"}"),
                            Does.Contain("DEECD123456789"));

                Assert.That(OPCPClientLogger.Redact(""),  Is.Empty);

            });

        }

        #endregion

    }

}
