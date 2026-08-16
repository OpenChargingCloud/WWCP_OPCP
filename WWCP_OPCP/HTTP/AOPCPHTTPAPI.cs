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
    /// What every OPCP service API has in common: it is reached with a bearer token, it answers
    /// JSON, and it refuses in the one shape the specification defines for refusals.
    ///
    /// The six services differ in their paths, their payloads and which roles may call them.
    /// Everything else lives here.
    /// </summary>
    public abstract class AOPCPHTTPAPI : HTTPAPI
    {

        #region Properties

        /// <summary>
        /// How this API decides whether to believe an access token.
        ///
        /// Optional, and when it is absent every request is served. That is a deliberate escape
        /// hatch for a development ecosystem, not a default: leaving it unset in anything
        /// reachable would publish the pool to whoever asks.
        /// </summary>
        public IAccessTokenValidator?  AccessTokenValidator    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP service API.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        /// <param name="Description">An optional description of this API.</param>
        protected AOPCPHTTPAPI(HTTPServer             HTTPServer,
                               IAccessTokenValidator? AccessTokenValidator   = null,
                               HTTPPath?              RootPath               = null,
                               I18NString?            Description            = null)

            : base(HTTPServer,
                   null,
                   AsMountPath(RootPath),
                   null,
                   Description)

        {

            this.AccessTokenValidator = AccessTokenValidator;

            OPCPContentTypes.Touch();

        }

        #endregion

        #region (private, static) AsMountPath(RootPath)

        /// <summary>
        /// Normalize where an API is mounted.
        /// </summary>
        /// <remarks>
        /// The mount path has to end in a slash. When the server hands a request to a mounted API
        /// it strips the mount path off the front by length, counting on that trailing slash to be
        /// there; without it the API receives a path one character short - "/v1/root" turns
        /// "/v1/root/rootCerts" into "t/rootCerts" - and nothing matches. Normalizing here means
        /// no caller has to know that.
        /// </remarks>
        private static HTTPPath AsMountPath(HTTPPath? RootPath)
        {

            var path = (RootPath ?? HTTPPath.Root).ToString();

            return HTTPPath.Parse(
                       path.EndsWith('/')
                           ? path
                           : path + "/"
                   );

        }

        #endregion


        #region (protected, static) Route(OperationPath)

        /// <summary>
        /// The route of one operation, relative to where this API is mounted.
        /// </summary>
        /// <param name="OperationPath">The path of an operation below the mount point, e.g. "rootCerts".</param>
        /// <remarks>
        /// Routes are registered relative to the mount point, not absolutely: the server strips an
        /// API's own root path from the request before handing it over, so a handler registered at
        /// the full path would be looking for that prefix twice and never match.
        /// </remarks>
        protected static HTTPPath Route(String OperationPath)

            => HTTPPath.Root + OperationPath;

        #endregion

        #region (protected) TryAuthenticate(Request, out TokenInfo, out Response)

        /// <summary>
        /// Check that the request carries a token this API believes.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        /// <param name="TokenInfo">What the token says its holder may do.</param>
        /// <param name="Response">The refusal to send back, when there is one.</param>
        protected Boolean TryAuthenticate(HTTPRequest                              Request,
                                          [NotNullWhen(true)]  out OPCPTokenInfo?  TokenInfo,
                                          [NotNullWhen(false)] out HTTPResponse?   Response)
        {

            TokenInfo  = null;
            Response   = null;

            if (AccessTokenValidator is null)
            {
                // No validator configured: every caller is anonymous and unrestricted.
                TokenInfo = new OPCPTokenInfo();
                return true;
            }

            if (Request.Authorization is not HTTPBearerAuthentication bearer)
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.Unauthorized,
                                  "This request carries no bearer token!");
                return false;
            }

            if (!AccessTokenValidator.TryValidate(bearer.Token, out TokenInfo, out var errorResponse))
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.Unauthorized,
                                  errorResponse);
                return false;
            }

            return true;

        }

        #endregion

        #region (protected) TryAuthorize   (Request, TokenInfo, Roles, out Response)

        /// <summary>
        /// Check that the caller acts in one of the roles this operation is open to.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        /// <param name="TokenInfo">What the token says its holder may do.</param>
        /// <param name="Response">The refusal to send back, when there is one.</param>
        /// <param name="Roles">The roles this operation is open to. None means every role.</param>
        protected Boolean TryAuthorize(HTTPRequest                             Request,
                                       OPCPTokenInfo                           TokenInfo,
                                       [NotNullWhen(false)] out HTTPResponse?  Response,
                                       params OPCPRole[]                       Roles)
        {

            Response = null;

            // With no validator there is nothing to authorize against, and an anonymous
            // caller of a development ecosystem is allowed everything.
            if (AccessTokenValidator is null || Roles.Length == 0)
                return true;

            if (!TokenInfo.HasAnyRole(Roles))
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.Forbidden,
                                  $"This operation is open to [{Roles.AggregateWith(", ")}], " +
                                  $"and the given token carries [{(TokenInfo.Roles.Any() ? TokenInfo.Roles.AggregateWith(", ") : "no roles")}]!");
                return false;
            }

            return true;

        }

        #endregion


        #region (protected) Respond(Request, HTTPStatusCode, JSON = null)

        /// <summary>
        /// Answer with JSON, or with a status and nothing else.
        /// </summary>
        /// <param name="Request">The request being answered.</param>
        /// <param name="HTTPStatusCode">The status code.</param>
        /// <param name="JSON">An optional JSON body.</param>
        protected HTTPResponse Respond(HTTPRequest     Request,
                                       HTTPStatusCode  HTTPStatusCode,
                                       JObject?        JSON             = null)
        {

            var builder = new HTTPResponse.Builder(Request) {
                              HTTPStatusCode            = HTTPStatusCode,
                              Server                    = HTTPServer?.HTTPServerName,
                              Date                      = Timestamp.Now,
                              AccessControlAllowOrigin  = "*",
                              AccessControlAllowHeaders = [ "Content-Type", "Accept", "Authorization" ],
                              Connection                = ConnectionType.KeepAlive
                          };

            if (JSON is not null)
            {
                builder.ContentType  = HTTPContentType.Application.JSON_UTF8;
                builder.Content      = JSON.ToUTF8Bytes();
            }

            return builder.AsImmutable;

        }

        #endregion

        #region (protected) Refuse (Request, HTTPStatusCode, ErrorMessages)

        /// <summary>
        /// Refuse in the shape the specification defines: the messages, and a trace identification
        /// to quote when asking the operator what happened.
        /// </summary>
        /// <param name="Request">The request being refused.</param>
        /// <param name="HTTPStatusCode">The status code.</param>
        /// <param name="ErrorMessages">What went wrong.</param>
        protected HTTPResponse Refuse(HTTPRequest       Request,
                                      HTTPStatusCode    HTTPStatusCode,
                                      params String[]   ErrorMessages)

            => Respond(
                   Request,
                   HTTPStatusCode,
                   new OPCPError(
                       ErrorMessages,
                       Trace_Id.NewRandom()
                   ).ToJSON()
               );

        #endregion

        #region (protected) TryParseJSONBody(Request, out JSON, out Response)

        /// <summary>
        /// Read the JSON body of a request.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        /// <param name="JSON">The parsed body.</param>
        /// <param name="Response">The refusal to send back, when there is one.</param>
        protected Boolean TryParseJSONBody(HTTPRequest                             Request,
                                           [NotNullWhen(true)]  out JObject?       JSON,
                                           [NotNullWhen(false)] out HTTPResponse?  Response)
        {

            JSON      = null;
            Response  = null;

            var body = Request.HTTPBodyAsUTF8String?.Trim();

            if (body.IsNullOrEmpty())
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.BadRequest,
                                  "This request carries no body!");
                return false;
            }

            try
            {
                JSON = JObject.Parse(body);
                return true;
            }
            catch (Exception e)
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.BadRequest,
                                  "The body of this request is not a JSON object: " + e.Message);
                return false;
            }

        }

        #endregion

        #region (protected) TryParseURLParameter<T>(Request, ParameterName, TryParser, Description, out Value, out Response)

        /// <summary>
        /// Read one identifier out of the request path.
        /// </summary>
        /// <typeparam name="T">The type of the identifier.</typeparam>
        /// <param name="Request">An HTTP request.</param>
        /// <param name="ParameterName">The name of the path parameter, as the URL template spells it.</param>
        /// <param name="TryParser">How to parse it.</param>
        /// <param name="Description">What it is, for the error message.</param>
        /// <param name="Value">The parsed identifier.</param>
        /// <param name="Response">The refusal to send back, when there is one.</param>
        /// <remarks>
        /// Path parameters are addressed by name rather than by position. Hermod's request also
        /// carries a positional ParsedURLParameters array, but the current server no longer fills
        /// it - reading a route parameter from there silently yields nothing.
        /// </remarks>
        protected Boolean TryParseURLParameter<T>(HTTPRequest                             Request,
                                                  String                                  ParameterName,
                                                  TryParser<T>                            TryParser,
                                                  String                                  Description,
                                                  [NotNullWhen(true)]  out T?             Value,
                                                  [NotNullWhen(false)] out HTTPResponse?  Response)
        {

            Value     = default;
            Response  = null;

            var text = Request.TryGetURLParameter(ParameterName);

            if (text.IsNullOrEmpty())
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.BadRequest,
                                  $"The {Description} is missing from the request path!");
                return false;
            }

            if (!TryParser(text, out Value) || Value is null)
            {
                Response = Refuse(Request,
                                  HTTPStatusCode.BadRequest,
                                  $"'{text}' is not a valid {Description}!");
                return false;
            }

            return true;

        }

        #endregion

    }

}
