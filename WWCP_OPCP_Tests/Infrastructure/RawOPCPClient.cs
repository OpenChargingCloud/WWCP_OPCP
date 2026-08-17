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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.Infrastructure
{

    /// <summary>
    /// An OPCP client that will send whatever it is told to.
    ///
    /// The typed clients are careful - a PCID that does not parse never leaves them, and neither
    /// does a certificate that is not one. That is the right behaviour and it makes them useless
    /// for testing what a service does when such a request arrives anyway, which is what this is
    /// for. It rides the same request pipeline as the real clients, so what reaches the service
    /// is a genuine OPCP request in every respect except its contents.
    /// </summary>
    public class RawOPCPClient : AOPCPHTTPClient
    {

        #region Constructor(s)

        /// <summary>
        /// Create a new raw OPCP client.
        /// </summary>
        /// <param name="RemoteURL">The base URL of the OPCP ecosystem.</param>
        /// <param name="AccessTokenProvider">An optional source of bearer tokens.</param>
        public RawOPCPClient(URL                    RemoteURL,
                             IAccessTokenProvider?  AccessTokenProvider   = null)

            : base(RemoteURL,
                   AccessTokenProvider)

        { }

        #endregion


        #region SendRaw(HTTPMethod, Path, RequestBody = null)

        /// <summary>
        /// Send one request and return whatever came back, unexamined.
        /// </summary>
        /// <param name="HTTPMethod">The HTTP method.</param>
        /// <param name="Path">The path to send it to, valid or not.</param>
        /// <param name="RequestBody">An optional JSON body, sensible or not.</param>
        public Task<HTTPResponse> SendRaw(HTTPMethod  HTTPMethod,
                                          String      Path,
                                          JObject?    RequestBody   = null)

            => Send(
                   HTTPMethod,
                   HTTPPath.Parse(Path),
                   RequestBody
               );

        #endregion

        #region SendRawBytes(HTTPMethod, Path, Content, ContentType)

        /// <summary>
        /// Send one request whose body is not JSON, and return whatever came back, unexamined.
        ///
        /// Enrollment is the part of OPCP that speaks PKCS#10 and PKCS#7 rather than JSON, and
        /// what a service does with a body that is neither is worth being able to ask.
        /// </summary>
        /// <param name="HTTPMethod">The HTTP method.</param>
        /// <param name="Path">The path to send it to, valid or not.</param>
        /// <param name="Content">The body, sensible or not.</param>
        /// <param name="ContentType">What to call it.</param>
        public Task<HTTPResponse> SendRawBytes(HTTPMethod        HTTPMethod,
                                               String            Path,
                                               Byte[]?           Content,
                                               HTTPContentType?  ContentType)

            => Send(
                   HTTPMethod,
                   HTTPPath.Parse(Path),
                   Content,
                   ContentType
               );

        #endregion

    }

}
