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

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.Auth
{

    /// <summary>
    /// The in-process token issuer that lets the whole ecosystem be tested without an identity
    /// provider, and the caching provider that keeps a client's token fresh.
    /// </summary>
    [TestFixture]
    public class TokenIssuerAndProviderTests
    {

        #region Data

        private static TestTokenIssuer NewIssuer()

            => new (URL.Parse("https://eu.plugncharge-qa.hubject.com"));

        #endregion


        #region An_issued_token_validates_and_says_what_it_permits()

        [Test]
        public void An_issued_token_validates_and_says_what_it_permits()
        {

            var issuer  = NewIssuer();

            var issued  = issuer.IssueToken(
                              Roles:        [ OPCPRole.OEM ],
                              WMIs:         [ WMI.Parse("ECD") ],
                              ProviderIds:  [ Provider_Id.Parse("DEECD") ],
                              ClientName:   "EC4D_Test_User",
                              Scopes:       [ "pcpservice", "rcpservice" ]
                          );

            Assert.That(issuer.TryValidate(issued.AccessToken, out var info, out var errorResponse),  Is.True, errorResponse);

            Assert.Multiple(() => {

                Assert.That(issued.TokenType,  Is.EqualTo("Bearer"));
                Assert.That(issued.ExpiresIn,  Is.EqualTo(TimeSpan.FromHours(24)));

                Assert.That(info!.HasRole(OPCPRole.OEM),                       Is.True);
                Assert.That(info.MayActFor(PCID.Parse("ECD12345671234567")),   Is.True);
                Assert.That(info.MayActFor(EMA_Id.Parse("DEECD123456789")),    Is.True);
                Assert.That(info.ClientName,  Is.EqualTo("EC4D_Test_User"));
                Assert.That(info.Audiences,   Is.EqualTo(new[] { "https://eu.plugncharge-qa.hubject.com" }));
                Assert.That(info.Scopes,      Is.EqualTo(new[] { "pcpservice", "rcpservice" }));

            });

        }

        #endregion

        #region A_token_issued_by_someone_else_is_refused()

        /// <summary>
        /// Two issuers mint independent signing keys, so a token from one must not open the other.
        /// </summary>
        [Test]
        public void A_token_issued_by_someone_else_is_refused()
        {

            var ours    = NewIssuer();
            var theirs  = NewIssuer();

            var token   = theirs.IssueToken(Roles: [ OPCPRole.Admin ]).AccessToken;

            Assert.Multiple(() => {
                Assert.That(theirs.TryValidate(token, out _, out _),               Is.True);
                Assert.That(ours.  TryValidate(token, out var info, out var why),  Is.False);
                Assert.That(info,  Is.Null);
                Assert.That(why,   Does.Contain("signature"));
            });

        }

        #endregion

        #region A_tampered_token_is_refused()

        /// <summary>
        /// Rewriting the claims of a signed token - here, promoting the holder to administrator -
        /// has to fail on the signature. Reading the claims still works, which is exactly why
        /// reading and trusting are separate operations in this library.
        /// </summary>
        [Test]
        public void A_tampered_token_is_refused()
        {

            var issuer    = NewIssuer();
            var original  = issuer.IssueToken(Roles: [ OPCPRole.CPO ]).AccessToken;
            var parts     = original.Split('.');

            Assert.That(Base64URL.TryDecodeUTF8(parts[1], out var payload),  Is.True);

            var tampered  = $"{parts[0]}.{Base64URL.Encode(payload.Replace("CPO", "Admin"))}.{parts[2]}";

            Assert.Multiple(() => {

                Assert.That(issuer.TryValidate(tampered, out _, out var why),  Is.False);
                Assert.That(why,  Does.Contain("signature"));

                // Decoding is not trusting: the forged claim is readable, and worthless.
                Assert.That(OPCPTokenInfo.TryParse(tampered, out var info, out _),  Is.True);
                Assert.That(info!.HasRole(OPCPRole.Admin),  Is.True);

            });

        }

        #endregion

        #region A_token_asking_for_no_signature_check_is_refused()

        /// <summary>
        /// The classic JWT attack: re-declare the algorithm as "none" and drop the signature.
        /// The issuer decides the algorithm, never the token.
        /// </summary>
        [Test]
        public void A_token_asking_for_no_signature_check_is_refused()
        {

            var issuer  = NewIssuer();
            var parts   = issuer.IssueToken(Roles: [ OPCPRole.CPO ]).AccessToken.Split('.');

            var none    = $"{Base64URL.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}")}.{parts[1]}.";

            Assert.Multiple(() => {
                Assert.That(issuer.TryValidate(none, out _, out var why),  Is.False);
                Assert.That(why,  Does.Contain("HS256"));
            });

        }

        #endregion

        #region An_expired_token_is_refused()

        [Test]
        public void An_expired_token_is_refused()
        {

            var issuer  = NewIssuer();

            var expired = issuer.IssueToken(
                              Roles:     [ OPCPRole.CPO ],
                              Lifetime:  TimeSpan.FromHours(1),
                              IssuedAt:  DateTimeOffset.UtcNow - TimeSpan.FromHours(2)
                          );

            Assert.Multiple(() => {
                Assert.That(issuer.TryValidate(expired.AccessToken, out _, out var why),  Is.False);
                Assert.That(why,  Does.Contain("expired"));
            });

        }

        #endregion

        #region A_request_without_a_bearer_token_is_refused()

        [Test]
        public void A_request_without_a_bearer_token_is_refused()
        {

            var issuer = NewIssuer();

            Assert.Multiple(() => {

                Assert.That(issuer.TryValidate((IHTTPAuthentication?) null, out _, out var why),  Is.False);
                Assert.That(why,  Does.Contain("no bearer token"));

                Assert.That(issuer.TryValidate(HTTPBasicAuthentication.Create("user", "password"), out _, out _),  Is.False);

                var token = issuer.IssueToken(Roles: [ OPCPRole.CPO ]).AccessToken;
                Assert.That(issuer.TryValidate(HTTPBearerAuthentication.Parse(token), out var info, out _),  Is.True);
                Assert.That(info!.HasRole(OPCPRole.CPO),  Is.True);

            });

        }

        #endregion


        #region A_valid_token_is_reused_rather_than_refetched()

        [Test]
        public async Task A_valid_token_is_reused_rather_than_refetched()
        {

            var issuer    = NewIssuer();
            var provider  = new ClientCredentialsTokenProvider(
                                _ => Task.FromResult(issuer.IssueToken(Roles: [ OPCPRole.CPO ]))
                            );

            var first     = await provider.GetAccessTokenAsync();
            var second    = await provider.GetAccessTokenAsync();
            var third     = await provider.GetAccessTokenAsync();

            Assert.Multiple(() => {
                Assert.That(second,             Is.EqualTo(first));
                Assert.That(third,              Is.EqualTo(first));
                Assert.That(provider.Renewals,  Is.EqualTo(1UL), "One token, fetched once.");
            });

        }

        #endregion

        #region A_token_near_expiry_is_renewed_early()

        /// <summary>
        /// A token that lapses while a request is in flight is refused on arrival, so the provider
        /// stops trusting one a safety margin before it actually expires.
        /// </summary>
        [Test]
        public async Task A_token_near_expiry_is_renewed_early()
        {

            var issuer    = NewIssuer();

            // Ten minutes of life left, but the provider will not use a token
            // within fifteen minutes of expiry.
            var provider  = new ClientCredentialsTokenProvider(
                                _             => Task.FromResult(issuer.IssueToken(Roles: [ OPCPRole.CPO ])),
                                SafetyMargin:    TimeSpan.FromMinutes(15),
                                InitialToken:    issuer.IssueToken(Roles:     [ OPCPRole.CPO ],
                                                                   Lifetime:  TimeSpan.FromMinutes(10))
                            );

            var stale     = provider.CurrentToken;
            var token     = await provider.GetAccessTokenAsync();

            Assert.Multiple(() => {
                Assert.That(provider.Renewals,     Is.EqualTo(1UL));
                Assert.That(token,                 Is.Not.EqualTo(stale!.AccessToken));
                Assert.That(provider.CurrentToken, Is.Not.SameAs(stale));
            });

        }

        #endregion

        #region Concurrent_callers_share_one_renewal()

        /// <summary>
        /// Twenty requests starting at once must produce one token, not twenty. Otherwise the
        /// first burst of traffic after a restart hammers the token endpoint.
        /// </summary>
        [Test]
        public async Task Concurrent_callers_share_one_renewal()
        {

            var issuer    = NewIssuer();

            var provider  = new ClientCredentialsTokenProvider(
                                async cancellationToken => {
                                    // Long enough that the other callers are certain to arrive
                                    // while this fetch is still running.
                                    await Task.Delay(50, cancellationToken);
                                    return issuer.IssueToken(Roles: [ OPCPRole.CPO ]);
                                }
                            );

            var tokens    = await Task.WhenAll(Enumerable.Range(0, 20).
                                                          Select(_ => provider.GetAccessTokenAsync()));

            Assert.Multiple(() => {
                Assert.That(provider.Renewals,      Is.EqualTo(1UL));
                Assert.That(tokens.Distinct(),      Has.Exactly(1).Items);
            });

        }

        #endregion

        #region An_invalidated_token_is_refetched()

        /// <summary>
        /// A service may stop honouring a token before it expires - revoked credentials, rotated
        /// keys. A client seeing 401 discards what it holds and asks again.
        /// </summary>
        [Test]
        public async Task An_invalidated_token_is_refetched()
        {

            var issuer    = NewIssuer();
            var issued    = 0;

            // The client name distinguishes the two tokens. Without something that differs, they
            // would be byte-identical: a JWT is a function of its claims, and two tokens minted
            // in the same second for the same client have the same claims down to the timestamp.
            var provider  = new ClientCredentialsTokenProvider(
                                _ => Task.FromResult(issuer.IssueToken(Roles:       [ OPCPRole.CPO ],
                                                                       ClientName:  $"client-{++issued}"))
                            );

            var first     = await provider.GetAccessTokenAsync();

            provider.Invalidate();

            Assert.That(provider.CurrentToken,  Is.Null);

            var second    = await provider.GetAccessTokenAsync();

            Assert.Multiple(() => {
                Assert.That(provider.Renewals,  Is.EqualTo(2UL));
                Assert.That(issued,             Is.EqualTo(2), "The delegate was asked twice.");
                Assert.That(second,             Is.Not.EqualTo(first));
            });

            provider.Dispose();

        }

        #endregion

        #region A_fixed_token_is_handed_out_unchanged()

        [Test]
        public async Task A_fixed_token_is_handed_out_unchanged()
        {

            var provider = new StaticAccessTokenProvider("eyJhbGciOiJIUzI1NiJ9.e30.x");

            Assert.Multiple(async () => {
                Assert.That(await provider.GetAccessTokenAsync(),  Is.EqualTo("eyJhbGciOiJIUzI1NiJ9.e30.x"));
                Assert.That(() => new StaticAccessTokenProvider(""),  Throws.ArgumentException);
            });

            await Task.CompletedTask;

        }

        #endregion


        #region Base64url_round_trips_and_rejects_what_it_should(Text)

        [TestCase("")]
        [TestCase("a")]
        [TestCase("ab")]
        [TestCase("abc")]
        [TestCase("abcd")]
        [TestCase("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")]
        [TestCase("Ärger mit Umlauten & Sonderzeichen +/=")]
        public void Base64url_round_trips_and_rejects_what_it_should(String Text)
        {

            var encoded = Base64URL.Encode(Text);

            Assert.Multiple(() => {
                Assert.That(encoded,  Does.Not.Contain("="), "The URL-safe form is unpadded.");
                Assert.That(encoded,  Does.Not.Contain("+"));
                Assert.That(encoded,  Does.Not.Contain("/"));
                Assert.That(Base64URL.TryDecodeUTF8(encoded, out var decoded),  Is.True);
                Assert.That(decoded,  Is.EqualTo(Text));
            });

        }

        #endregion

    }

}
