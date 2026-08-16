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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// Authenticating against the ecosystem, over the wire, and then using what came back.
    /// </summary>
    [TestFixture]
    public class AccessTokenEndpointTests : AOPCPEcosystemTests
    {

        #region A_registered_client_is_issued_a_usable_token()

        [Test]
        public async Task A_registered_client_is_issued_a_usable_token()
        {

            tokenAPI.RegisterClient(
                "an-oem",
                "a-secret",
                Roles:        [ OPCPRole.OEM ],
                WMIs:         [ WMI.Parse("ECD") ],
                ProviderIds:  [ Provider_Id.Parse("DEECD") ],
                ClientName:   "EC4D_Test_User",
                Scopes:       [ "rcpservice", "pcpservice" ]
            );

            var client    = new AccessTokenClient(endpointConfig.TokenEndpoint);
            var response  = await client.IssueToken("an-oem", "a-secret", endpointConfig.Audience);

            Assert.That(response.IsSuccess,  Is.True, response.Error?.ToString());

            var issued = response.Data!;

            Assert.Multiple(() => {

                Assert.That(issued.TokenType,  Is.EqualTo("Bearer"));
                Assert.That(issued.ExpiresIn,  Is.EqualTo(TimeSpan.FromHours(24)));
                Assert.That(issued.Scopes,     Is.EquivalentTo(new[] { "rcpservice", "pcpservice" }));

                // The token the endpoint issued says what the client registered for.
                Assert.That(OPCPTokenInfo.TryParse(issued.AccessToken, out var info, out _),  Is.True);
                Assert.That(info!.HasRole(OPCPRole.OEM),                      Is.True);
                Assert.That(info.MayActFor(PCID.Parse("ECD12345671234567")),  Is.True);
                Assert.That(info.MayActFor(EMA_Id.Parse("DEECD123456789")),   Is.True);
                Assert.That(info.ClientName,  Is.EqualTo("EC4D_Test_User"));

            });

        }

        #endregion

        #region The_whole_chain_works_from_credentials_to_a_served_request()

        /// <summary>
        /// What a real client actually does: hand it a client identification and secret, and it
        /// authenticates itself, carries the token, and gets served - with nothing in the test
        /// touching a token by hand.
        /// </summary>
        [Test]
        public async Task The_whole_chain_works_from_credentials_to_a_served_request()
        {

            tokenAPI.RegisterClient("an-admin", "a-secret", Roles: [ OPCPRole.Admin ]);

            using var tokenProvider = AccessTokenClient.CreateTokenProvider(
                                          endpointConfig,
                                          "an-admin",
                                          "a-secret"
                                      );

            var rcp      = new RCP_HTTPClient(endpointConfig, tokenProvider);

            var added    = await rcp.SaveRootCA(NewRootCA("V2G Root CA Test"), RootCertificateType.V2G);
            var listed   = await rcp.GetAllRootCerts();

            Assert.Multiple(() => {

                Assert.That(added.IsSuccess,   Is.True, added.Error?.ToString());
                Assert.That(listed.IsSuccess,  Is.True, listed.Error?.ToString());
                Assert.That(listed.Data,       Has.Exactly(1).Items);

                // Two service calls, one token: the provider fetched once and kept it.
                Assert.That(tokenProvider.Renewals,      Is.EqualTo(1UL));
                Assert.That(tokenProvider.CurrentToken,  Is.Not.Null);

            });

        }

        #endregion

        #region Wrong_credentials_are_refused(ClientId, ClientSecret)

        /// <summary>
        /// An unknown client and a wrong secret get the same answer. Telling them apart would
        /// make the endpoint a directory of who exists.
        /// </summary>
        [TestCase("a-client",   "the-wrong-secret")]
        [TestCase("no-such-client", "a-secret")]
        public async Task Wrong_credentials_are_refused(String ClientId, String ClientSecret)
        {

            tokenAPI.RegisterClient("a-client", "a-secret", Roles: [ OPCPRole.CPO ]);

            var client    = new AccessTokenClient(endpointConfig.TokenEndpoint);
            var response  = await client.IssueToken(ClientId, ClientSecret, endpointConfig.Audience);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,             Is.False);
                Assert.That(response.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.Unauthorized));
                Assert.That(response.Error!.FirstMessage,   Does.Contain("Unauthorized"));
            });

        }

        #endregion

        #region A_token_for_another_deployment_is_refused()

        /// <summary>
        /// The audience names the stage and world region a token is for. Issuing one for a
        /// deployment this endpoint does not serve would produce a token nothing accepts.
        /// </summary>
        [Test]
        public async Task A_token_for_another_deployment_is_refused()
        {

            tokenAPI.RegisterClient("a-client", "a-secret", Roles: [ OPCPRole.CPO ]);

            var client    = new AccessTokenClient(endpointConfig.TokenEndpoint);

            var response  = await client.IssueToken("a-client",
                                                    "a-secret",
                                                    URL.Parse("https://eu.plugncharge-qa.hubject.com"));

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("issues tokens for"));
            });

        }

        #endregion

        #region An_unusable_client_fails_loudly_rather_than_silently()

        /// <summary>
        /// A client that cannot authenticate must not carry on unauthenticated and be refused one
        /// request at a time - the first thing it does should say what is actually wrong.
        /// </summary>
        [Test]
        public void An_unusable_client_fails_loudly_rather_than_silently()
        {

            using var tokenProvider = AccessTokenClient.CreateTokenProvider(
                                          endpointConfig,
                                          "nobody",
                                          "nothing"
                                      );

            var rcp = new RCP_HTTPClient(endpointConfig, tokenProvider);

            // The failure surfaces as a transport-level failure of the first call, carrying
            // the token endpoint's own words.
            var response = rcp.GetAllRootCerts().GetAwaiter().GetResult();

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.Error!.FirstMessage,  Does.Contain("Unauthorized"));
                Assert.That(tokenProvider.CurrentToken,    Is.Null);
            });

        }

        #endregion

    }

}
