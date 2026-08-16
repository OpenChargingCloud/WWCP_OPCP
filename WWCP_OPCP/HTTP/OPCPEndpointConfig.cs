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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Where an OPCP ecosystem lives.
    ///
    /// None of the eight interface documents names a server - every one of them ships an empty
    /// <c>servers</c> list - so the address is something a deployment configures rather than
    /// something a client can read off the specification. What the specification does describe is
    /// the shape:
    ///
    /// <code>
    /// https://{region}.{stage}.{domain}/{version}/{service}/{object}
    /// </code>
    ///
    /// with the version, service and object already baked into every path. This type composes the
    /// part in front of them, and can equally be pointed at an address of an entirely different
    /// shape - which is what talking to any ecosystem other than the one the specification was
    /// written for requires.
    /// </summary>
    public class OPCPEndpointConfig
    {

        #region Properties

        /// <summary>
        /// Where the six OPCP services live, without a trailing slash,
        /// e.g. "https://eu.plugncharge-qa.hubject.com".
        /// </summary>
        public URL  BaseURL        { get; }

        /// <summary>
        /// The OAuth2 audience to ask a token for. Identical to the base URL in the deployment
        /// the specification documents.
        /// </summary>
        public URL  Audience       { get; }

        /// <summary>
        /// The full URL of the OAuth2 token endpoint.
        /// </summary>
        public URL  TokenEndpoint  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP endpoint configuration.
        /// </summary>
        /// <param name="BaseURL">Where the six OPCP services live.</param>
        /// <param name="TokenEndpoint">The OAuth2 token endpoint, otherwise "{BaseURL}/oauth/token".</param>
        /// <param name="Audience">The OAuth2 audience, otherwise the base URL.</param>
        public OPCPEndpointConfig(URL   BaseURL,
                                  URL?  TokenEndpoint   = null,
                                  URL?  Audience        = null)
        {

            var baseURL = URL.Parse(BaseURL.ToString().TrimEnd('/'));

            this.BaseURL        = baseURL;
            this.Audience       = Audience      ?? baseURL;
            this.TokenEndpoint  = TokenEndpoint ?? URL.Parse($"{baseURL}/oauth/token");

        }

        #endregion


        #region (static) Create  (Region, Stage, Domain = "hubject.com", ...)

        /// <summary>
        /// Compose an endpoint configuration from the three parts the specification asks
        /// consumers to keep configurable.
        /// </summary>
        /// <param name="Region">The global region, e.g. "eu" or "us".</param>
        /// <param name="Stage">The system stage, e.g. "plugncharge-qa".</param>
        /// <param name="Domain">The domain, "hubject.com" for the ecosystem the specification documents.</param>
        /// <param name="TokenEndpoint">An optional OAuth2 token endpoint.</param>
        /// <param name="Audience">An optional OAuth2 audience.</param>
        public static OPCPEndpointConfig Create(String  Region,
                                                String  Stage,
                                                String  Domain          = "hubject.com",
                                                URL?    TokenEndpoint   = null,
                                                URL?    Audience        = null)
        {

            if (Region.IsNullOrEmpty())
                throw new ArgumentException("The given region must not be null or empty!", nameof(Region));

            if (Stage.IsNullOrEmpty())
                throw new ArgumentException("The given stage must not be null or empty!",  nameof(Stage));

            if (Domain.IsNullOrEmpty())
                throw new ArgumentException("The given domain must not be null or empty!", nameof(Domain));

            return new OPCPEndpointConfig(
                       URL.Parse($"https://{Region}.{Stage}.{Domain}"),
                       TokenEndpoint,
                       Audience
                   );

        }

        #endregion

        #region (static) Hubject (Region, Stage)

        /// <summary>
        /// The ecosystem the specification was written for.
        /// </summary>
        /// <param name="Region">The global region, e.g. "eu" or "us".</param>
        /// <param name="Stage">The system stage, e.g. "plugncharge-qa".</param>
        /// <remarks>
        /// The token endpoint is a separate host from the services, and it does not carry the
        /// stage: the example token of accessToken.v1.json was issued by
        /// <c>https://auth.eu.plugncharge.hubject.com/</c> for the audience
        /// <c>https://eu.plugncharge-qa.hubject.com</c>. That one worked example is the whole of
        /// the evidence for this default, so pass a token endpoint explicitly if a deployment
        /// tells you otherwise.
        /// </remarks>
        public static OPCPEndpointConfig Hubject(String  Region,
                                                 String  Stage)

            => Create(
                   Region,
                   Stage,
                   "hubject.com",
                   TokenEndpoint:  URL.Parse($"https://auth.{Region}.plugncharge.hubject.com/oauth/token")
               );

        #endregion


        #region Static definitions

        /// <summary>The European test stage.</summary>
        public static OPCPEndpointConfig  EU_Test        => Hubject("eu", "plugncharge-test");

        /// <summary>The European quality assurance stage.</summary>
        public static OPCPEndpointConfig  EU_QA          => Hubject("eu", "plugncharge-qa");

        /// <summary>The European production stage.</summary>
        public static OPCPEndpointConfig  EU_Production  => Hubject("eu", "plugncharge");

        /// <summary>The US test stage.</summary>
        public static OPCPEndpointConfig  US_Test        => Hubject("us", "plugncharge-test");

        /// <summary>The US quality assurance stage.</summary>
        public static OPCPEndpointConfig  US_QA          => Hubject("us", "plugncharge-qa");

        /// <summary>The US production stage.</summary>
        public static OPCPEndpointConfig  US_Production  => Hubject("us", "plugncharge");

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => BaseURL.ToString();

        #endregion

    }

}
