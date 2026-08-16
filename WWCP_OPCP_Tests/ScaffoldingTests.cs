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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests
{

    /// <summary>
    /// That the three libraries this implementation stands on are reachable and working
    /// from the test assembly: Illias for JSON and identifiers, Hermod for HTTP and its
    /// PKI factory, and BouncyCastle underneath both. Everything after this assumes it.
    /// </summary>
    [TestFixture]
    public class ScaffoldingTests
    {

        #region Illias_JSON_helpers_are_reachable()

        /// <summary>
        /// Every OPCP data structure is serialized through JSONObject.Create, which drops
        /// null and empty properties - that is how optional fields are left out.
        /// </summary>
        [Test]
        public void Illias_JSON_helpers_are_reachable()
        {

            var json = JSONObject.Create(
                           new JProperty("rootType",       "V2G"),
                           new JProperty("commonName",     "V2G Root CA G2"),
                           null
                       );

            Assert.Multiple(() => {
                Assert.That(json.Value<String>("rootType"),    Is.EqualTo("V2G"));
                Assert.That(json.Value<String>("commonName"),  Is.EqualTo("V2G Root CA G2"));
                Assert.That(json.Properties().Count(),         Is.EqualTo(2), "Null properties must be dropped.");
            });

        }

        #endregion

        #region Hermod_HTTP_primitives_are_reachable()

        /// <summary>
        /// OPCP endpoints are composed from a configurable base URL and the version prefix
        /// baked into every path of the specification.
        /// </summary>
        [Test]
        public void Hermod_HTTP_primitives_are_reachable()
        {

            var url   = URL.     Parse("https://eu.plugncharge-qa.hubject.com");
            var path  = HTTPPath.Parse("/v1/root/rootCerts");

            Assert.Multiple(() => {
                Assert.That(url. ToString(),  Is.EqualTo("https://eu.plugncharge-qa.hubject.com"));
                Assert.That(path.ToString(),  Is.EqualTo("/v1/root/rootCerts"));
            });

        }

        #endregion

        #region EST_media_types_register_themselves()

        /// <summary>
        /// EST speaks 'application/pkcs10' and 'application/pkcs7-mime', neither of which
        /// Hermod knows up front. Parsing an unknown media type registers it, so the EST
        /// client and API need no special casing - this is that assumption, tested.
        /// </summary>
        [Test]
        public void EST_media_types_register_themselves()
        {

            Assert.Multiple(() => {

                Assert.That(HTTPContentType.TryParse("application/pkcs10", out var pkcs10),  Is.True);
                Assert.That(pkcs10?.MediaMainType,  Is.EqualTo("application"));
                Assert.That(pkcs10?.MediaSubType,   Is.EqualTo("pkcs10"));

                Assert.That(HTTPContentType.TryParse("application/pkcs7-mime; smime-type=certs-only", out var pkcs7),  Is.True);
                Assert.That(pkcs7?.MediaMainType,   Is.EqualTo("application"));
                Assert.That(pkcs7?.MediaSubType,    Is.EqualTo("pkcs7-mime"));

            });

        }

        #endregion

        #region BouncyCastle_generates_the_ISO_15118_curves()

        /// <summary>
        /// The three signature algorithms OPCP names for root certificates and EST enrollment.
        /// Ed448 is the one .NET itself cannot do, which is why BouncyCastle is here at all.
        /// </summary>
        [TestCase("secp256r1")]
        [TestCase("secp521r1")]
        public void BouncyCastle_generates_the_ISO_15118_curves(String CurveName)
        {

            var keyPair = PKIFactory.GenerateECCKeyPair(CurveName);

            Assert.Multiple(() => {
                Assert.That(keyPair.Private.IsPrivate,  Is.True);
                Assert.That(keyPair.Public. IsPrivate,  Is.False);
            });

        }

        /// <summary>
        /// Ed448, the third algorithm of the OPCP root certificate and EST enrollment enums.
        /// </summary>
        [Test]
        public void BouncyCastle_generates_Ed448_keys()
        {

            var keyPair = PKIFactory.GenerateEd448KeyPair();

            Assert.Multiple(() => {
                Assert.That(keyPair.Private.IsPrivate,  Is.True);
                Assert.That(keyPair.Public. IsPrivate,  Is.False);
            });

        }

        #endregion

    }

}
