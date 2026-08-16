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

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Which revision of Hubject's Open Plug&amp;Charge Protocol (OPCP) this library implements.
    ///
    /// OPCP is published as a set of OpenAPI documents plus narrative markdown, without a
    /// changelog and without git tags: the release is named only by its folder, and each
    /// interface document carries its own <c>info.version</c>. Both are recorded here, so
    /// that updating the specification submodule fails a test instead of passing silently.
    /// </summary>
    public static class OPCPSpecification
    {

        #region Data

        /// <summary>
        /// The OPCP release implemented by this library, matching the release
        /// directory of the specification repository ("OPCP-{Release}").
        /// </summary>
        public const  String  Release        = "1.0.0";

        /// <summary>
        /// The specification repository this library was written against.
        /// </summary>
        public const  String  RepositoryURL  = "https://github.com/hubject/opcp";

        /// <summary>
        /// The OpenAPI version every OPCP interface document is written in.
        /// </summary>
        public const  String  OpenAPIVersion = "3.0.0";

        #endregion

        #region (class) DocumentVersions

        /// <summary>
        /// The <c>info.version</c> of each OPCP interface document.
        /// These advance independently of the release as a whole.
        /// </summary>
        public static class DocumentVersions
        {

            /// <summary>The OAuth2 token endpoint (accessToken.v1.json).</summary>
            public const  String  AccessToken     = "1.0";

            /// <summary>The Root Certificate Pool (rcp.v1.json).</summary>
            public const  String  RCP             = "1.1";

            /// <summary>The (OEM) Provisioning Certificate Pool (pcp.v1.json).</summary>
            public const  String  PCP             = "1.0";

            /// <summary>The Certificate Provisioning Service (cps.v1.json).</summary>
            public const  String  CPS             = "1.0";

            /// <summary>The Contract Certificate Pool (ccp.v1.json).</summary>
            public const  String  CCP             = "1.0";

            /// <summary>Enrollment over Secure Transport, RFC 7030 (est.v1.json).</summary>
            public const  String  EST             = "1.0";

            /// <summary>The webhook subscription management API (webhooks.v1.json).</summary>
            public const  String  Webhooks        = "1.0";

            /// <summary>The webhook callback contract, implemented by the receiving partner
            /// rather than by the ecosystem operator (webhook.payload.v1.json).</summary>
            public const  String  WebhookPayload  = "1.0.1";

        }

        #endregion

    }

}
