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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A freshly issued OPCP access token.
    /// </summary>
    /// <remarks>
    /// <code>
    /// { "access_token": "eyJhbGciOiJSUzI1NiIs...",
    ///   "scope":        "rcpservice ccpservice pcpservice cpservice pkigateway",
    ///   "expires_in":   86400,
    ///   "token_type":   "Bearer" }
    /// </code>
    /// All four are required. Tokens are valid for 24 hours.
    /// </remarks>
    public class AccessTokenResponse
    {

        #region Properties

        /// <summary>
        /// The token itself, a JSON Web Token.
        /// </summary>
        [Mandatory]
        public String          AccessToken    { get; }

        /// <summary>
        /// The scopes this token opens, separated by spaces.
        /// </summary>
        [Mandatory]
        public String          Scope          { get; }

        /// <summary>
        /// How long the token remains valid, in seconds.
        /// </summary>
        [Mandatory]
        public TimeSpan        ExpiresIn      { get; }

        /// <summary>
        /// The type of the token, "Bearer".
        /// </summary>
        [Mandatory]
        public String          TokenType      { get; }

        /// <summary>
        /// When this token was received.
        /// </summary>
        public DateTimeOffset  ReceivedAt     { get; }


        /// <summary>
        /// When this token stops being valid, computed from when it arrived.
        /// </summary>
        public DateTimeOffset  ExpiresAt
            => ReceivedAt + ExpiresIn;

        /// <summary>
        /// The scopes as individual words.
        /// </summary>
        public IEnumerable<String> Scopes
            => Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new access token response.
        /// </summary>
        /// <param name="AccessToken">The token itself.</param>
        /// <param name="Scope">The scopes this token opens.</param>
        /// <param name="ExpiresIn">How long the token remains valid.</param>
        /// <param name="TokenType">The type of the token.</param>
        /// <param name="ReceivedAt">An optional moment the token arrived, otherwise now.</param>
        public AccessTokenResponse(String           AccessToken,
                                   String           Scope,
                                   TimeSpan         ExpiresIn,
                                   String           TokenType,
                                   DateTimeOffset?  ReceivedAt    = null)
        {

            if (AccessToken.IsNullOrEmpty())
                throw new ArgumentException("The given access token must not be null or empty!", nameof(AccessToken));

            this.AccessToken  = AccessToken;
            this.Scope        = Scope     ?? "";
            this.ExpiresIn    = ExpiresIn;
            this.TokenType    = TokenType ?? "Bearer";
            this.ReceivedAt   = ReceivedAt ?? DateTimeOffset.UtcNow;

        }

        #endregion


        #region IsValidAt(Timestamp, SafetyMargin = null)

        /// <summary>
        /// Whether this token is still usable at the given moment.
        /// </summary>
        /// <param name="Timestamp">A moment in time.</param>
        /// <param name="SafetyMargin">
        /// How long before expiry to stop considering the token usable. A token that expires while
        /// a request is in flight is refused by the server, so a provider renews slightly early.
        /// </param>
        public Boolean IsValidAt(DateTimeOffset  Timestamp,
                                 TimeSpan?       SafetyMargin   = null)

            => Timestamp < ExpiresAt - (SafetyMargin ?? TimeSpan.Zero);

        #endregion

        #region (static) TryParse(JSON, out AccessTokenResponse, out ErrorResponse, ReceivedAt = null, CustomAccessTokenResponseParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of an access token response.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="AccessTokenResponse">The parsed access token response.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="ReceivedAt">An optional moment the token arrived, otherwise now.</param>
        /// <param name="CustomAccessTokenResponseParser">An optional delegate to parse custom access token responses.</param>
        public static Boolean TryParse(JObject                                            JSON,
                                       [NotNullWhen(true)]  out AccessTokenResponse?      AccessTokenResponse,
                                       [NotNullWhen(false)] out String?                   ErrorResponse,
                                       DateTimeOffset?                                    ReceivedAt                        = null,
                                       CustomJObjectParserDelegate<AccessTokenResponse>?  CustomAccessTokenResponseParser   = null)
        {

            try
            {

                AccessTokenResponse = null;

                #region AccessToken    [mandatory]

                if (!JSON.ParseMandatoryText("access_token",
                                             "access token",
                                             out String? AccessToken,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region Scope          [mandatory]

                if (!JSON.ParseMandatoryText("scope",
                                             "scope",
                                             out String? Scope,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region ExpiresIn      [mandatory]

                if (!JSON.ParseMandatory("expires_in",
                                         "expires in",
                                         out UInt64 ExpiresIn,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region TokenType      [mandatory]

                if (!JSON.ParseMandatoryText("token_type",
                                             "token type",
                                             out String? TokenType,
                                             out ErrorResponse))
                {
                    return false;
                }

                #endregion


                AccessTokenResponse = new AccessTokenResponse(
                                          AccessToken,
                                          Scope,
                                          TimeSpan.FromSeconds(ExpiresIn),
                                          TokenType,
                                          ReceivedAt
                                      );

                if (CustomAccessTokenResponseParser is not null)
                    AccessTokenResponse = CustomAccessTokenResponseParser(JSON, AccessTokenResponse);

                return true;

            }
            catch (Exception e)
            {
                AccessTokenResponse  = null;
                ErrorResponse        = "The given JSON representation of an access token response is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomAccessTokenResponseSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomAccessTokenResponseSerializer">A delegate to serialize custom access token responses.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<AccessTokenResponse>? CustomAccessTokenResponseSerializer = null)
        {

            var json = JSONObject.Create(
                           new JProperty("access_token",  AccessToken),
                           new JProperty("scope",         Scope),
                           new JProperty("expires_in",    (UInt64) ExpiresIn.TotalSeconds),
                           new JProperty("token_type",    TokenType)
                       );

            return CustomAccessTokenResponseSerializer is not null
                       ? CustomAccessTokenResponseSerializer(this, json)
                       : json;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object - without the token.
        /// </summary>
        public override String ToString()

            => $"{TokenType} token for [{Scope}], expiring {ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC";

        #endregion

    }

}
