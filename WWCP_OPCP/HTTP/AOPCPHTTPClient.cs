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

using System.Diagnostics;
using System.Security.Authentication;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Parse the payload of a successful OPCP response.
    /// </summary>
    /// <typeparam name="T">The type of the payload.</typeparam>
    /// <param name="JSON">The JSON body of the response.</param>
    /// <param name="Data">The parsed payload.</param>
    /// <param name="ErrorResponse">Why the body could not be read.</param>
    public delegate Boolean OPCPPayloadParser<T>(JObject JSON, out T? Data, out String? ErrorResponse);


    /// <summary>
    /// What every typed OPCP client has in common: it carries a bearer token, it speaks JSON,
    /// and whatever it asks for either arrives or comes back as the operator's own refusal.
    ///
    /// The six services differ in their paths and payloads and in nothing else, so the request
    /// pipeline lives here once.
    /// </summary>
    public abstract class AOPCPHTTPClient : AHTTPClient
    {

        #region Data

        /// <summary>
        /// The default HTTP user agent.
        /// </summary>
        public new const String DefaultHTTPUserAgent = "GraphDefined WWCP OPCP HTTP Client";

        #endregion

        #region Properties

        /// <summary>
        /// Where this client gets the bearer token for its next request.
        ///
        /// Optional, because the token endpoint itself is reached without one - and because
        /// an ecosystem under test may not be checking.
        /// </summary>
        public IAccessTokenProvider?  AccessTokenProvider    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP HTTP client.
        /// </summary>
        /// <param name="RemoteURL">The remote URL of the OPCP service.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        /// <param name="Description">An optional description of this client.</param>
        /// <param name="HTTPUserAgent">An optional HTTP user agent.</param>
        /// <param name="RemoteCertificateValidator">An optional validator of the remote TLS certificate.</param>
        /// <param name="TLSProtocols">The optional TLS protocols to allow.</param>
        /// <param name="RequestTimeout">An optional request timeout.</param>
        /// <param name="MaxNumberOfRetries">The optional maximum number of transmission retries.</param>
        /// <param name="DisableLogging">Whether to disable logging.</param>
        protected AOPCPHTTPClient(URL                                                        RemoteURL,
                                  IAccessTokenProvider?                                      AccessTokenProvider          = null,
                                  I18NString?                                                Description                  = null,
                                  String?                                                    HTTPUserAgent                = null,
                                  RemoteTLSServerCertificateValidationHandler<IHTTPClient>?  RemoteCertificateValidator   = null,
                                  SslProtocols?                                              TLSProtocols                 = null,
                                  TimeSpan?                                                  RequestTimeout               = null,
                                  UInt16?                                                    MaxNumberOfRetries           = null,
                                  Boolean?                                                   DisableLogging               = null)

            : base(RemoteURL,
                   Description,
                   HTTPUserAgent ?? DefaultHTTPUserAgent,
                   null,
                   AcceptTypes.FromHTTPContentTypes(HTTPContentType.Application.JSON_UTF8),
                   HTTPContentType.Application.JSON_UTF8,
                   null,
                   null,

                   TLSProtocols:                 TLSProtocols,
                   RemoteCertificateValidator:   RemoteCertificateValidator,
                   MaxNumberOfRetries:           MaxNumberOfRetries,
                   DisableLogging:               DisableLogging)

        {

            this.AccessTokenProvider = AccessTokenProvider;

            if (RequestTimeout.HasValue)
                this.RequestTimeout = RequestTimeout.Value;

            // The enrollment and revocation media types have to be known before a response
            // naming one of them arrives.
            OPCPContentTypes.Touch();

        }

        #endregion


        #region (protected) PathOf  (OperationPath)

        /// <summary>
        /// Combine the deployment's own path prefix with the path of an operation.
        ///
        /// The specification's own addresses put the services at the root, so the prefix is
        /// usually empty - but nothing says an ecosystem cannot live under a path, and the
        /// interface documents name no server at all to say otherwise.
        /// </summary>
        /// <param name="OperationPath">The path of an operation, e.g. "/v1/root/rootCerts".</param>
        protected HTTPPath PathOf(String OperationPath)

            => RemoteURL.Path + OperationPath;

        #endregion

        #region (protected) Query   (HTTPMethod, Path, ParseResponse, ...)

        /// <summary>
        /// Send a request and read what came back.
        /// </summary>
        /// <typeparam name="T">The type of the payload.</typeparam>
        /// <param name="HTTPMethod">The HTTP method.</param>
        /// <param name="Path">The path of the operation.</param>
        /// <param name="ParseResponse">How to read a successful response body.</param>
        /// <param name="RequestBody">An optional JSON request body.</param>
        /// <param name="QueryString">An optional query string.</param>
        /// <param name="RequestBuilder">An optional delegate to add headers to the request.</param>
        /// <param name="PayloadRequired">
        /// Whether a successful response must carry a readable payload. False for the operations
        /// the specification documents without a response body, where a service answering with
        /// one is welcome but not required.
        /// </param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        protected async Task<OPCPResponse<T>> Query<T>(HTTPMethod                    HTTPMethod,
                                                       HTTPPath                      Path,
                                                       OPCPPayloadParser<T>          ParseResponse,
                                                       JObject?                      RequestBody         = null,
                                                       QueryString?                  QueryString         = null,
                                                       Action<HTTPRequest.Builder>?  RequestBuilder      = null,
                                                       Boolean                       PayloadRequired     = true,
                                                       EventTracking_Id?             EventTrackingId     = null,
                                                       CancellationToken             CancellationToken   = default)
        {

            var eventTrackingId  = EventTrackingId ?? EventTracking_Id.New;
            var startTime        = DateTimeOffset.UtcNow;
            var stopwatch        = Stopwatch.StartNew();

            try
            {

                var httpResponse = await Send(
                                             HTTPMethod,
                                             Path,
                                             RequestBody,
                                             QueryString,
                                             RequestBuilder,
                                             eventTrackingId,
                                             CancellationToken
                                         ).ConfigureAwait(false);

                stopwatch.Stop();

                #region The service refused

                if (!IsSuccessful(httpResponse.HTTPStatusCode))
                    return OPCPResponse<T>.Failed(
                               ParseError(httpResponse),
                               httpResponse.HTTPStatusCode,
                               startTime,
                               stopwatch.Elapsed,
                               eventTrackingId,
                               httpResponse
                           );

                #endregion

                #region The service answered

                if (!TryReadJSON(httpResponse, out var json, out var jsonError))
                    return PayloadRequired
                               ? OPCPResponse<T>.Failed(
                                     OPCPError.Create(jsonError),
                                     httpResponse.HTTPStatusCode,
                                     startTime,
                                     stopwatch.Elapsed,
                                     eventTrackingId,
                                     httpResponse
                                 )
                               : OPCPResponse<T>.Success(
                                     default!,
                                     httpResponse.HTTPStatusCode,
                                     startTime,
                                     stopwatch.Elapsed,
                                     eventTrackingId,
                                     httpResponse
                                 );

                if (!ParseResponse(json, out var data, out var parseError) || data is null)
                    return PayloadRequired
                               ? OPCPResponse<T>.Failed(
                                     OPCPError.Create(parseError ?? "The response of the OPCP service could not be read!"),
                                     httpResponse.HTTPStatusCode,
                                     startTime,
                                     stopwatch.Elapsed,
                                     eventTrackingId,
                                     httpResponse
                                 )
                               : OPCPResponse<T>.Success(
                                     default!,
                                     httpResponse.HTTPStatusCode,
                                     startTime,
                                     stopwatch.Elapsed,
                                     eventTrackingId,
                                     httpResponse
                                 );

                return OPCPResponse<T>.Success(
                           data,
                           httpResponse.HTTPStatusCode,
                           startTime,
                           stopwatch.Elapsed,
                           eventTrackingId,
                           httpResponse
                       );

                #endregion

            }
            catch (Exception e)
            {

                stopwatch.Stop();

                return OPCPResponse<T>.Failed(
                           OPCPError.Create($"The OPCP request failed: {e.Message}"),
                           HTTPStatusCode.BadGateway,
                           startTime,
                           stopwatch.Elapsed,
                           eventTrackingId
                       );

            }

        }

        #endregion

        #region (protected) Command (HTTPMethod, Path, ...)

        /// <summary>
        /// Send a request whose success is the answer - the operations that reply with a
        /// status and no body.
        /// </summary>
        /// <param name="HTTPMethod">The HTTP method.</param>
        /// <param name="Path">The path of the operation.</param>
        /// <param name="RequestBody">An optional JSON request body.</param>
        /// <param name="QueryString">An optional query string.</param>
        /// <param name="RequestBuilder">An optional delegate to add headers to the request.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        protected async Task<OPCPResponse> Command(HTTPMethod                    HTTPMethod,
                                                   HTTPPath                      Path,
                                                   JObject?                      RequestBody         = null,
                                                   QueryString?                  QueryString         = null,
                                                   Action<HTTPRequest.Builder>?  RequestBuilder      = null,
                                                   EventTracking_Id?             EventTrackingId     = null,
                                                   CancellationToken             CancellationToken   = default)
        {

            var eventTrackingId  = EventTrackingId ?? EventTracking_Id.New;
            var startTime        = DateTimeOffset.UtcNow;
            var stopwatch        = Stopwatch.StartNew();

            try
            {

                var httpResponse = await Send(
                                             HTTPMethod,
                                             Path,
                                             RequestBody,
                                             QueryString,
                                             RequestBuilder,
                                             eventTrackingId,
                                             CancellationToken
                                         ).ConfigureAwait(false);

                stopwatch.Stop();

                return IsSuccessful(httpResponse.HTTPStatusCode)

                           ? OPCPResponse.Success(
                                 httpResponse.HTTPStatusCode,
                                 startTime,
                                 stopwatch.Elapsed,
                                 eventTrackingId,
                                 httpResponse
                             )

                           : OPCPResponse.Failed(
                                 ParseError(httpResponse),
                                 httpResponse.HTTPStatusCode,
                                 startTime,
                                 stopwatch.Elapsed,
                                 eventTrackingId,
                                 httpResponse
                             );

            }
            catch (Exception e)
            {

                stopwatch.Stop();

                return OPCPResponse.Failed(
                           OPCPError.Create($"The OPCP request failed: {e.Message}"),
                           HTTPStatusCode.BadGateway,
                           startTime,
                           stopwatch.Elapsed,
                           eventTrackingId
                       );

            }

        }

        #endregion

        #region (protected) Send    (HTTPMethod, Path, ...)

        /// <summary>
        /// Send one request, with a bearer token when this client has one to offer.
        /// </summary>
        protected async Task<HTTPResponse> Send(HTTPMethod                    HTTPMethod,
                                                HTTPPath                      Path,
                                                JObject?                      RequestBody         = null,
                                                QueryString?                  QueryString         = null,
                                                Action<HTTPRequest.Builder>?  RequestBuilder      = null,
                                                EventTracking_Id?             EventTrackingId     = null,
                                                CancellationToken             CancellationToken   = default)
        {

            IHTTPAuthentication? authentication = null;

            if (AccessTokenProvider is not null)
                authentication = HTTPBearerAuthentication.Parse(
                                     await AccessTokenProvider.GetAccessTokenAsync(CancellationToken).ConfigureAwait(false)
                                 );

            return await RunRequest(
                             HTTPMethod,
                             Path,
                             QueryString,
                             null,
                             authentication,
                             RequestBody?.ToUTF8Bytes(),
                             RequestBody is not null
                                 ? HTTPContentType.Application.JSON_UTF8
                                 : null,
                             RequestBuilder:    RequestBuilder,
                             EventTrackingId:   EventTrackingId,
                             CancellationToken: CancellationToken
                         ).ConfigureAwait(false);

        }

        #endregion


        #region (protected, static) IsSuccessful(HTTPStatusCode)

        /// <summary>
        /// Whether a status code means the request was honoured.
        /// </summary>
        protected static Boolean IsSuccessful(HTTPStatusCode HTTPStatusCode)

            => HTTPStatusCode.Code >= 200 &&
               HTTPStatusCode.Code <  300;

        #endregion

        #region (protected, static) TryReadJSON(HTTPResponse, out JSON, out ErrorResponse)

        /// <summary>
        /// Read the body of a response as a JSON object.
        /// </summary>
        protected static Boolean TryReadJSON(HTTPResponse  HTTPResponse,
                                             out JObject   JSON,
                                             out String    ErrorResponse)
        {

            JSON           = [];
            ErrorResponse  = "";

            var body = HTTPResponse.HTTPBodyAsUTF8String?.Trim();

            if (body.IsNullOrEmpty())
            {
                ErrorResponse = "The OPCP service answered with an empty body!";
                return false;
            }

            try
            {
                JSON = JObject.Parse(body);
                return true;
            }
            catch (Exception e)
            {
                ErrorResponse = "The OPCP service answered with something that is not a JSON object: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (protected, static) ParseError (HTTPResponse)

        /// <summary>
        /// Read a refusal.
        ///
        /// Two shapes are understood: the one every OPCP service defines, and OAuth2's own
        /// 'error' plus 'error_description', which is what the token endpoint answers with -
        /// it is an OAuth2 endpoint before it is an OPCP one.
        ///
        /// A gateway between here and the service may answer with prose or with nothing at all.
        /// Losing the status code because the body was not what was expected would leave a caller
        /// with no idea what happened, so anything unrecognized becomes an error naming the status
        /// and quoting whatever did arrive.
        /// </summary>
        protected static OPCPError ParseError(HTTPResponse HTTPResponse)
        {

            var body = HTTPResponse.HTTPBodyAsUTF8String?.Trim();

            if (body.IsNotNullOrEmpty())
            {
                try
                {

                    var json = JObject.Parse(body);

                    #region An OAuth2 refusal

                    var oauthError = json.Value<String>("error");

                    if (oauthError.IsNotNullOrEmpty())
                        return new OPCPError([
                                   json.Value<String>("error_description") ?? oauthError!,
                                   oauthError!
                               ]);

                    #endregion

                    if (OPCPError.TryParse(json, out var opcpError, out _) &&
                        (opcpError.ErrorMessages.Any() || opcpError.TraceId.HasValue))
                    {
                        return opcpError;
                    }

                }
                catch
                { }
            }

            return new OPCPError([
                       $"HTTP {HTTPResponse.HTTPStatusCode.Code} {HTTPResponse.HTTPStatusCode.Name}",
                       .. body.IsNotNullOrEmpty() ? new[] { body! } : []
                   ]);

        }

        #endregion

    }

}
