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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The other end of a webhook: the "simple payload-service with public endpoint" the
    /// specification asks a partner to provide.
    ///
    /// It exists here because a partner should not have to work out the signature check from a Go
    /// snippet and a Java snippet that disagree about which header to read. It is also what lets a
    /// whole ecosystem be tested with events actually arriving somewhere.
    /// </summary>
    public class WebhookReceiver_HTTPAPI : HTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the receiver is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/payload/");

        #endregion

        #region Properties

        /// <summary>
        /// The secret the sender signs with. Without one, every delivery is refused: an endpoint
        /// that accepts unsigned events accepts events from anybody.
        /// </summary>
        public String?  Secret            { get; set; }

        /// <summary>
        /// What to answer with, for a partner backend that wants to say it could not take an
        /// event - and for anything that wants to watch a sender retry.
        /// </summary>
        public HTTPStatusCode  AnswerWith { get; set; } = HTTPStatusCode.OK;

        /// <summary>
        /// How many deliveries arrived here, counting the ones that were refused.
        /// </summary>
        public Int32    Deliveries        { get; private set; }

        #endregion

        #region Events

        /// <summary>
        /// An event arrived and its signature was good.
        /// </summary>
        public event Func<WebhookEvent, Task>?  OnEvent;

        /// <summary>
        /// Something arrived that was not acceptable, and why.
        /// </summary>
        public event Func<String, Task>?        OnRefused;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook receiver.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Secret">The secret the sender signs with.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public WebhookReceiver_HTTPAPI(HTTPServer  HTTPServer,
                                       String?     Secret     = null,
                                       HTTPPath?   RootPath   = null)

            : base(HTTPServer,
                   null,
                   AsMountPath(RootPath ?? DefaultRootPath),
                   null,
                   I18NString.Create("OPCP Webhook Receiver"))

        {

            this.Secret = Secret;

            AddHandler(
                HTTPMethod.POST,
                HTTPPath.Root,
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: Receive
            );

        }

        #endregion


        #region (private) Receive(Request)

        /// <summary>
        /// Take one delivery, after checking that whoever sent it holds this endpoint's secret.
        /// </summary>
        private async Task<HTTPResponse> Receive(HTTPRequest Request)
        {

            Deliveries++;

            var body = Request.HTTPBody ?? [];

            #region The signature, before anything else is looked at

            if (Secret.IsNullOrEmpty())
                return await Refuse(Request, "This receiver has no secret, so no delivery can be believed.");

            if (!WebhookDeliveryService.VerifySignature(body,
                                                        Secret!,
                                                        WebhookDeliveryService.SignatureOf(Request)))
            {
                // 401 rather than 400, and before the body is parsed at all: an unsigned delivery
                // is not a malformed event, it is an event from somebody who cannot prove they
                // are the ecosystem.
                return await Refuse(Request, "The signature of this delivery is missing or wrong.");
            }

            #endregion

            JObject json;

            try
            {
                json = JObject.Parse(Request.HTTPBodyAsUTF8String ?? "");
            }
            catch (Exception e)
            {
                return await Refuse(Request, "The body of this delivery is not a JSON object: " + e.Message,
                                    HTTPStatusCode.BadRequest);
            }

            if (!WebhookEvent.TryParse(json, out var webhookEvent, out var errorResponse))
                return await Refuse(Request, errorResponse, HTTPStatusCode.BadRequest);

            if (OnEvent is not null)
                await OnEvent.Invoke(webhookEvent);

            return Answer(Request, AnswerWith);

        }

        #endregion

        #region (private) Refuse (Request, Reason, StatusCode = Unauthorized)

        private async Task<HTTPResponse> Refuse(HTTPRequest      Request,
                                                String           Reason,
                                                HTTPStatusCode?  StatusCode   = null)
        {

            if (OnRefused is not null)
                await OnRefused.Invoke(Reason);

            return Answer(Request, StatusCode ?? HTTPStatusCode.Unauthorized);

        }

        #endregion

        #region (private) Answer (Request, StatusCode)

        private HTTPResponse Answer(HTTPRequest     Request,
                                    HTTPStatusCode  StatusCode)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = StatusCode,
                   Server          = HTTPServer?.HTTPServerName,
                   Date            = Timestamp.Now,
                   Connection      = ConnectionType.KeepAlive
               }.AsImmutable;

        #endregion

        #region (private, static) AsMountPath(RootPath)

        /// <summary>
        /// A mount path has to end in a slash - the server strips it off a request by length and
        /// counts on that slash being there.
        /// </summary>
        private static HTTPPath AsMountPath(HTTPPath RootPath)
        {

            var path = RootPath.ToString();

            return HTTPPath.Parse(
                       path.EndsWith('/')
                           ? path
                           : path + "/"
                   );

        }

        #endregion

    }

}
