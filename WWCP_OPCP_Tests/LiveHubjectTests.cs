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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests
{

    /// <summary>
    /// The clients pointed at a real OPCP ecosystem rather than at the one this suite builds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Excluded from every ordinary run - by the category the build instructions filter on, and by
    /// <c>[Explicit]</c> on top of that. A test that reaches the public internet has no business
    /// failing somebody's build because a certificate rolled over or a network was slow.
    /// </para>
    /// <para>
    /// Everything comes from the environment, because credentials do not belong in a repository:
    /// </para>
    /// <code>
    /// OPCP_BASE_URL        e.g. https://open.plugncharge-test.hubject.com
    /// OPCP_CLIENT_ID
    /// OPCP_CLIENT_SECRET
    /// </code>
    /// <para>
    /// Only reads: nothing here writes into an ecosystem somebody else operates.
    /// </para>
    /// </remarks>
    [TestFixture]
    [Explicit("Talks to a real OPCP ecosystem. Needs OPCP_BASE_URL, OPCP_CLIENT_ID and OPCP_CLIENT_SECRET.")]
    [Category("LiveHubject")]
    public class LiveHubjectTests
    {

        #region Data

        private URL                 baseURL;
        private OPCPEndpointConfig  endpointConfig  = null!;
        private String              clientId        = "";
        private String              clientSecret    = "";

        [OneTimeSetUp]
        public void ReadTheEnvironment()
        {

            var url       = Environment.GetEnvironmentVariable("OPCP_BASE_URL");
            clientId      = Environment.GetEnvironmentVariable("OPCP_CLIENT_ID")     ?? "";
            clientSecret  = Environment.GetEnvironmentVariable("OPCP_CLIENT_SECRET") ?? "";

            if (url.IsNullOrEmpty() || clientId.IsNullOrEmpty() || clientSecret.IsNullOrEmpty())
                Assert.Ignore("OPCP_BASE_URL, OPCP_CLIENT_ID and OPCP_CLIENT_SECRET have to be set for the live tests.");

            baseURL         = URL.Parse(url!);
            endpointConfig  = new OPCPEndpointConfig(baseURL);

        }

        /// <summary>
        /// A token provider that fetches and refreshes a real token, exactly as a deployment does.
        /// </summary>
        private IAccessTokenProvider Tokens()

            => AccessTokenClient.CreateTokenProvider(endpointConfig, clientId, clientSecret);

        #endregion


        #region The_token_endpoint_answers()

        /// <summary>
        /// Nothing else can be tried until this works, so it is the first thing to try.
        /// </summary>
        [Test]
        public async Task The_token_endpoint_answers()
        {

            var response = await new AccessTokenClient(endpointConfig.TokenEndpoint).IssueToken(
                                     clientId,
                                     clientSecret,
                                     endpointConfig.Audience
                                 );

            Assert.That(response.IsSuccess,  Is.True, response.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(response.Data!.AccessToken,  Is.Not.Empty);
                Assert.That(response.Data.TokenType,     Is.EqualTo("Bearer").IgnoreCase);
                Assert.That(response.Data.ExpiresIn,     Is.GreaterThan(TimeSpan.Zero));
            });

        }

        #endregion

        #region The_root_certificate_pool_hands_out_anchors_this_library_can_read()

        /// <summary>
        /// The one thing worth proving against a real ecosystem: that certificates issued by
        /// somebody else's PKI parse here, curves and all.
        /// </summary>
        [Test]
        public async Task The_root_certificate_pool_hands_out_anchors_this_library_can_read()
        {

            var roots = await new RCP_HTTPClient(baseURL, Tokens()).GetAllRootCerts();

            Assert.That(roots.IsSuccess,  Is.True, roots.Error?.ToString());
            Assert.That(roots.Data,       Is.Not.Empty);

            Assert.Multiple(() => {
                foreach (var root in roots.Data!)
                {
                    Assert.That(root.Certificate.CommonName,         Is.Not.Empty);
                    Assert.That(root.Certificate.SHA256Fingerprint,  Has.Length.EqualTo(64));
                    Assert.That(root.Certificate.IsCertificateAuthority,  Is.True,
                                $"'{root.Certificate.CommonName}' is in the root pool and is not a certification authority!");
                }
            });

        }

        #endregion

        #region The_provisioning_service_publishes_signers_this_library_can_read()

        [Test]
        public async Task The_provisioning_service_publishes_signers_this_library_can_read()
        {

            var signers = await new CPS_HTTPClient(baseURL, Tokens()).GetAllCpsSigners();

            Assert.That(signers.IsSuccess,  Is.True, signers.Error?.ToString());

            Assert.Multiple(() => {
                foreach (var signer in signers.Data ?? [])
                {
                    Assert.That(signer.Certificate.CommonName,             Is.Not.Empty);
                    Assert.That(signer.CpsRootDistinguishedName,           Is.Not.Empty);
                    Assert.That(signer.Certificate.NotAfter,               Is.GreaterThan(DateTimeOffset.UtcNow),
                                $"The published signer '{signer.Certificate.CommonName}' has expired!");
                }
            });

        }

        #endregion

        #region The_enrollment_service_hands_out_a_chain_this_library_can_verify()

        [Test]
        public async Task The_enrollment_service_hands_out_a_chain_this_library_can_verify()
        {

            var chain = await new EST_HTTPClient(baseURL, Tokens()).CACerts(
                                  CA_Id.Parse(CA_Type.CPO),
                                  SignatureAlgorithm.secp256r1
                              );

            Assert.That(chain.IsSuccess,  Is.True, chain.Error?.ToString());

            var certificates = chain.Data!.ToArray();

            Assert.That(certificates,  Is.Not.Empty);

            // Whatever came back has to be a path: each one issued by the next, ending in a root
            // that issued itself.
            Assert.Multiple(() => {

                for (var i = 0; i < certificates.Length - 1; i++)
                    Assert.That(certificates[i].IssuerName,
                                Is.EqualTo(certificates[i + 1].SubjectName),
                                $"'{certificates[i].CommonName}' is not issued by '{certificates[i + 1].CommonName}'!");

                Assert.That(certificates[^1].SubjectName,  Is.EqualTo(certificates[^1].IssuerName),
                            "The last one should be the self-signed root.");

            });

        }

        #endregion

    }

}
