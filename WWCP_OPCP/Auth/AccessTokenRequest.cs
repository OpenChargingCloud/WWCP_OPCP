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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Asking an OPCP ecosystem for an access token, by OAuth2 client credentials.
    /// </summary>
    /// <remarks>
    /// <code>
    /// { "client_id":     "...",
    ///   "client_secret": "...",
    ///   "audience":      "https://eu.plugncharge-qa.hubject.com",
    ///   "grant_type":    "client_credentials" }
    /// </code>
    /// All four are required. The audience names the stage and world region the token is for -
    /// a token minted for one stage does not open another.
    /// </remarks>
    public class AccessTokenRequest
    {

        #region Data

        /// <summary>
        /// The only grant type OPCP uses.
        /// </summary>
        public const String ClientCredentials = "client_credentials";

        #endregion

        #region Properties

        /// <summary>
        /// The identification of the client.
        /// </summary>
        [Mandatory]
        public String  ClientId       { get; }

        /// <summary>
        /// The secret of the client.
        /// </summary>
        [Mandatory]
        public String  ClientSecret   { get; }

        /// <summary>
        /// The stage and world region this token is for.
        /// </summary>
        [Mandatory]
        public URL     Audience       { get; }

        /// <summary>
        /// The OAuth2 grant type, always "client_credentials".
        /// </summary>
        [Mandatory]
        public String  GrantType      { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new access token request.
        /// </summary>
        /// <param name="ClientId">The identification of the client.</param>
        /// <param name="ClientSecret">The secret of the client.</param>
        /// <param name="Audience">The stage and world region this token is for.</param>
        /// <param name="GrantType">An optional grant type, otherwise "client_credentials".</param>
        public AccessTokenRequest(String   ClientId,
                                  String   ClientSecret,
                                  URL      Audience,
                                  String?  GrantType      = null)
        {

            if (ClientId.IsNullOrEmpty())
                throw new ArgumentException("The given client identification must not be null or empty!", nameof(ClientId));

            if (ClientSecret.IsNullOrEmpty())
                throw new ArgumentException("The given client secret must not be null or empty!",         nameof(ClientSecret));

            this.ClientId      = ClientId;
            this.ClientSecret  = ClientSecret;
            this.Audience      = Audience;
            this.GrantType     = GrantType ?? ClientCredentials;

        }

        #endregion


        #region (static) TryParse(JSON, out AccessTokenRequest, out ErrorResponse, CustomAccessTokenRequestParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of an access token request.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="AccessTokenRequest">The parsed access token request.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomAccessTokenRequestParser">An optional delegate to parse custom access token requests.</param>
        public static Boolean TryParse(JObject                                           JSON,
                                       [NotNullWhen(true)]  out AccessTokenRequest?      AccessTokenRequest,
                                       [NotNullWhen(false)] out String?                  ErrorResponse,
                                       CustomJObjectParserDelegate<AccessTokenRequest>?  CustomAccessTokenRequestParser   = null)
        {

            try
            {

                AccessTokenRequest = null;

                #region ClientId        [mandatory]

                if (!JSON.ParseMandatoryText("client_id",
                                             "client identification",
                                             out String? ClientId,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region ClientSecret    [mandatory]

                if (!JSON.ParseMandatoryText("client_secret",
                                             "client secret",
                                             out String? ClientSecret,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region Audience        [mandatory]

                if (!JSON.ParseMandatory("audience",
                                         "audience",
                                         URL.TryParse,
                                         out URL Audience,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region GrantType       [mandatory]

                if (!JSON.ParseMandatoryText("grant_type",
                                             "grant type",
                                             out String? GrantType,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion


                AccessTokenRequest = new AccessTokenRequest(
                                         ClientId,
                                         ClientSecret,
                                         Audience,
                                         GrantType
                                     );

                if (CustomAccessTokenRequestParser is not null)
                    AccessTokenRequest = CustomAccessTokenRequestParser(JSON, AccessTokenRequest);

                return true;

            }
            catch (Exception e)
            {
                AccessTokenRequest  = null;
                ErrorResponse       = "The given JSON representation of an access token request is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomAccessTokenRequestSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomAccessTokenRequestSerializer">A delegate to serialize custom access token requests.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<AccessTokenRequest>? CustomAccessTokenRequestSerializer = null)
        {

            var json = JSONObject.Create(
                           new JProperty("client_id",      ClientId),
                           new JProperty("client_secret",  ClientSecret),
                           new JProperty("audience",       Audience.ToString()),
                           new JProperty("grant_type",     GrantType)
                       );

            return CustomAccessTokenRequestSerializer is not null
                       ? CustomAccessTokenRequestSerializer(this, json)
                       : json;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object - without the secret.
        /// </summary>
        public override String ToString()

            => $"'{ClientId}' for {Audience} ({GrantType})";

        #endregion

    }

}
