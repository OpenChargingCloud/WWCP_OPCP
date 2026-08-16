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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.Auth
{

    /// <summary>
    /// Obtaining an OPCP access token, and reading what it permits.
    /// </summary>
    [TestFixture]
    public class AccessTokenTests
    {

        #region The_token_request_of_the_specification_round_trips()

        [Test]
        public void The_token_request_of_the_specification_round_trips()
        {

            var json = JObject.Parse("""
                                     {
                                       "client_id":     "tbzKdWxuPU6yia9koc5S0f0SM1zjdi1A",
                                       "client_secret": "a-secret",
                                       "audience":      "https://eu.plugncharge-qa.hubject.com",
                                       "grant_type":    "client_credentials"
                                     }
                                     """);

            Assert.That(AccessTokenRequest.TryParse(json, out var request, out var errorResponse),  Is.True, errorResponse);

            Assert.Multiple(() => {
                Assert.That(request!.ClientId,      Is.EqualTo("tbzKdWxuPU6yia9koc5S0f0SM1zjdi1A"));
                Assert.That(request.Audience.ToString(),  Is.EqualTo("https://eu.plugncharge-qa.hubject.com"));
                Assert.That(request.GrantType,      Is.EqualTo("client_credentials"));
                Assert.That(request.ToJSON(),       Is.EqualTo(json).Using<JToken>(JToken.DeepEquals));
                Assert.That(request.ToString(),     Does.Not.Contain("a-secret"), "The secret must not appear in a log line.");
            });

        }

        #endregion

        #region A_missing_field_of_the_token_request_is_refused(PropertyName)

        [TestCase("client_id")]
        [TestCase("client_secret")]
        [TestCase("audience")]
        [TestCase("grant_type")]
        public void A_missing_field_of_the_token_request_is_refused(String PropertyName)
        {

            var json = JObject.Parse("""
                                     {
                                       "client_id":     "abcd",
                                       "client_secret": "abcd",
                                       "audience":      "https://eu.plugncharge-qa.hubject.com",
                                       "grant_type":    "client_credentials"
                                     }
                                     """);

            json.Remove(PropertyName);

            Assert.Multiple(() => {
                Assert.That(AccessTokenRequest.TryParse(json, out _, out var errorResponse),  Is.False);
                Assert.That(errorResponse,  Is.Not.Null.And.Contains(PropertyName.Replace('_', ' ')));
            });

        }

        #endregion

        #region The_token_response_of_the_specification_round_trips()

        [Test]
        public void The_token_response_of_the_specification_round_trips()
        {

            var receivedAt  = DateTimeOffset.UnixEpoch;
            var json        = JObject.Parse("""
                                            {
                                              "access_token": "eyJhbGciOiJIUzI1NiJ9.e30.x",
                                              "scope":        "rcpservice ccpservice pcpservice cpservice pkigateway",
                                              "expires_in":   86400,
                                              "token_type":   "Bearer"
                                            }
                                            """);

            Assert.That(AccessTokenResponse.TryParse(json, out var response, out var errorResponse, receivedAt),  Is.True, errorResponse);

            Assert.Multiple(() => {
                Assert.That(response!.ExpiresIn,  Is.EqualTo(TimeSpan.FromHours(24)), "OPCP tokens last 24 hours.");
                Assert.That(response.ExpiresAt,   Is.EqualTo(receivedAt + TimeSpan.FromHours(24)));
                Assert.That(response.TokenType,   Is.EqualTo("Bearer"));
                Assert.That(response.Scopes,      Has.Exactly(5).Items);
                Assert.That(response.Scopes,      Has.Member("pkigateway"));
                Assert.That(response.ToJSON(),    Is.EqualTo(json).Using<JToken>(JToken.DeepEquals));
                Assert.That(response.ToString(),  Does.Not.Contain("eyJhbGciOiJIUzI1NiJ9"), "The token must not appear in a log line.");
            });

        }

        #endregion

        #region The_specifications_own_example_token_is_decoded()

        /// <summary>
        /// accessToken.v1.json publishes a real - long since expired - QA token. Decoding it is the
        /// only check available that this library reads the claims a live ecosystem actually issues,
        /// rather than the claims it was assumed to issue.
        /// </summary>
        [Test]
        public void The_specifications_own_example_token_is_decoded()
        {

            SpecificationRepository.IgnoreWhenUnavailable();

            var document  = SpecificationRepository.ReadDocument("accessToken.v1.json");

            var token     = document["paths"]?["/oauth/token"]?["post"]?["responses"]?["200"]?
                                    ["content"]?["application/json"]?["examples"]?["Token Response"]?
                                    ["value"]?["access_token"]?.Value<String>();

            Assert.That(token,  Is.Not.Null.And.Not.Empty, "The example token has moved within accessToken.v1.json.");

            Assert.That(OPCPTokenInfo.TryParse(token!, out var info, out var errorResponse),  Is.True, errorResponse);

            Assert.Multiple(() => {

                // The five roles of the example, four known and one an operator's own name.
                Assert.That(info!.Roles,  Has.Exactly(5).Items);
                Assert.That(info.HasRole(OPCPRole.CPO),             Is.True);
                Assert.That(info.HasRole(OPCPRole.OEM),             Is.True);
                Assert.That(info.HasRole(OPCPRole.MO_V2GPKI),       Is.True);
                Assert.That(info.HasRole(OPCPRole.MO_ExternalPKI),  Is.True);
                Assert.That(info.HasRole(OPCPRole.Admin),           Is.False);

                // The namespaced claims, found by their last segment rather than by a
                // hard-coded operator URL.
                Assert.That(info.WMIs,         Is.EqualTo(new[] { WMI.Parse("ECD") }));
                Assert.That(info.ProviderIds,  Is.EqualTo(new[] { Provider_Id.Parse("DEECD") }));
                Assert.That(info.ClientName,   Is.EqualTo("EC4D_Test_User"));

                Assert.That(info.Issuer,       Is.EqualTo("https://auth.eu.plugncharge.hubject.com/"));
                Assert.That(info.Audiences,    Is.EqualTo(new[] { "https://eu.plugncharge-qa.hubject.com" }));
                Assert.That(info.Subject,      Does.EndWith("@clients"));
                Assert.That(info.Scopes,       Has.Member("rcpservice"));

                // Issued for 24 hours, in March 2021.
                Assert.That(info.ExpiresAt - info.IssuedAt,           Is.EqualTo(TimeSpan.FromHours(24)));
                Assert.That(info.IsExpiredAt(DateTimeOffset.UtcNow),  Is.True, "This token expired in 2021.");

            });

        }

        #endregion

        #region The_authorization_scopes_of_the_example_token_are_enforced()

        /// <summary>
        /// The example token permits the WMI 'ECD' and the provider 'DEECD' and nothing else.
        /// This is the check the pools make before letting a caller touch a vehicle or a contract.
        /// </summary>
        [Test]
        public void The_authorization_scopes_of_the_example_token_are_enforced()
        {

            var info = new OPCPTokenInfo(
                           Roles:        [ OPCPRole.OEM ],
                           WMIs:         [ WMI.Parse("ECD") ],
                           ProviderIds:  [ Provider_Id.Parse("DEECD") ]
                       );

            Assert.Multiple(() => {

                Assert.That(info.MayActFor(PCID.Parse("ECD12345671234567")),   Is.True);
                Assert.That(info.MayActFor(PCID.Parse("ecd12345671234567")),   Is.True,  "The manufacturer prefix is case-insensitive.");
                Assert.That(info.MayActFor(PCID.Parse("XYZ12345671234567")),   Is.False, "Another manufacturer's vehicle.");

                Assert.That(info.MayActFor(EMA_Id.Parse("DEECD123456789")),    Is.True);
                Assert.That(info.MayActFor(EMA_Id.Parse("DE-ECD-123456789")),  Is.True,  "However the EMAID was written.");
                Assert.That(info.MayActFor(EMA_Id.Parse("DEXYZ123456789")),    Is.False, "Another provider's contract.");

                Assert.That(info.HasAnyRole(OPCPRole.OEM, OPCPRole.CPO),       Is.True);
                Assert.That(info.HasAnyRole(OPCPRole.CPO, OPCPRole.Admin),     Is.False);

            });

        }

        #endregion

        #region A_claim_holding_a_whole_identifier_still_names_its_prefix()

        /// <summary>
        /// The claims are documented as prefixes and the example carries prefixes, but a
        /// deployment putting a whole PCID or EMAID there means the same manufacturer or provider.
        /// </summary>
        [Test]
        public void A_claim_holding_a_whole_identifier_still_names_its_prefix()
        {

            var info = OPCPTokenInfo.FromClaims(JObject.Parse("""
                                                              {
                                                                "https://pnc.example.org/pcid":  [ "ECD12345671234567" ],
                                                                "https://pnc.example.org/emaid": [ "DEECD123456789" ]
                                                              }
                                                              """));

            Assert.Multiple(() => {
                Assert.That(info.WMIs,         Is.EqualTo(new[] { WMI.Parse("ECD") }));
                Assert.That(info.ProviderIds,  Is.EqualTo(new[] { Provider_Id.Parse("DEECD") }));
            });

        }

        #endregion

        #region Malformed_tokens_are_refused(Token)

        [TestCase("",                     Description = "empty")]
        [TestCase("not-a-token",          Description = "no parts")]
        [TestCase("only.two",             Description = "two parts")]
        [TestCase("a.b.c.d",              Description = "four parts")]
        [TestCase("aaa.!!!not-base64.cc", Description = "payload is not base64url")]
        [TestCase("aaa.bm90IEpTT04.cc",   Description = "payload is not JSON")]
        public void Malformed_tokens_are_refused(String Token)
        {

            Assert.Multiple(() => {
                Assert.That(OPCPTokenInfo.TryParse(Token, out var info, out var errorResponse),  Is.False);
                Assert.That(info,           Is.Null);
                Assert.That(errorResponse,  Is.Not.Null.And.Not.Empty);
            });

        }

        #endregion

    }

}
