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
    /// Serves an <see cref="OCSPResponder"/> over HTTP, as RFC 6960 describes.
    ///
    /// Deliberately unauthenticated: the specification requires the V2G PKI's responders to answer
    /// without a token, and it is right to. A revocation check that needed credentials would stop
    /// working at the moment a compromised credential made it matter most.
    /// </summary>
    public class OCSP_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the responder is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/ocsp/");

        #endregion

        #region Properties

        /// <summary>
        /// What actually answers.
        /// </summary>
        public OCSPResponder  Responder    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OCSP responder endpoint.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Responder">What answers the requests.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public OCSP_HTTPAPI(HTTPServer     HTTPServer,
                            OCSPResponder  Responder,
                            HTTPPath?      RootPath     = null)

            : base(HTTPServer,
                   null,   // RFC 6960 responders answer unauthenticated
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP OCSP Responder"))

        {

            this.Responder = Responder ?? throw new ArgumentNullException(nameof(Responder));

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region POST    ~/ocsp/

            AddHandler(
                HTTPMethod.POST,
                HTTPPath.Root,
                OPCPContentTypes.OCSPRequest,
                HTTPDelegate: request => {

                    if (request.HTTPBody is null || request.HTTPBody.Length == 0)
                        return Task.FromResult(
                                   new HTTPResponse.Builder(request) {
                                       HTTPStatusCode  = HTTPStatusCode.BadRequest,
                                       Server          = HTTPServer?.HTTPServerName,
                                       Date            = Timestamp.Now,
                                       Connection      = ConnectionType.KeepAlive
                                   }.AsImmutable
                               );

                    // The responder turns a malformed request into an OCSP response saying so,
                    // rather than into an HTTP error: that is what RFC 6960 asks for, and it is
                    // what a client parsing OCSP rather than HTTP can actually read.
                    return Task.FromResult(
                               new HTTPResponse.Builder(request) {
                                   HTTPStatusCode  = HTTPStatusCode.OK,
                                   Server          = HTTPServer?.HTTPServerName,
                                   Date            = Timestamp.Now,
                                   ContentType     = OPCPContentTypes.OCSPResponse,
                                   Content         = Responder.Respond(request.HTTPBody),
                                   Connection      = ConnectionType.KeepAlive
                               }.AsImmutable
                           );

                }
            );

            #endregion

        }

        #endregion

    }

}
