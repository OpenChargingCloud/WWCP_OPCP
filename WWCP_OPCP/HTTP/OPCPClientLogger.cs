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

using System.Text.RegularExpressions;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Writes down what an OPCP client sent and what came back - without writing down the things
    /// that would let whoever reads the log take the client's place.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One logger for all six services rather than one per service: they differ in their paths and
    /// their payloads and in nothing a log line cares about.
    /// </para>
    /// <para>
    /// <b>What is left out is the point.</b> Every OPCP request carries a bearer token, the token
    /// endpoint's own traffic carries the credential that mints them, and a webhook registration
    /// comes back with a signing secret. Any of those in a log file is the whole credential,
    /// reusable by whoever finds it - so they are elided before anything is written, and bodies
    /// are not logged at all unless a deployment asks for them.
    /// </para>
    /// </remarks>
    public class OPCPClientLogger
    {

        #region Data

        /// <summary>
        /// What replaces something that must not be written down.
        /// </summary>
        public const String Redacted = "[redacted]";

        private static readonly Regex authorization  = new (@"^(?<name>Authorization\s*:\s*)(?<scheme>\S+)\s+\S+\s*$",
                                                            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);

        private static readonly Regex jsonSecrets    = new (@"""(?<name>secret|access_token|refresh_token|client_secret|password)""\s*:\s*""[^""]*""",
                                                            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex formSecrets    = new (@"\b(?<name>client_secret|password)=[^&\s]*",
                                                            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private readonly Action<String>  sink;

        #endregion

        #region Properties

        /// <summary>
        /// Whether to write the bodies as well as the headers.
        /// </summary>
        /// <remarks>
        /// Off by default. A body is where a signing secret, a token response and a wrapped
        /// contract key travel; the known secrets are elided even when this is on, but a
        /// deployment turning it on should know what it is turning on.
        /// </remarks>
        public Boolean  LogBodies    { get; }

        /// <summary>
        /// How many exchanges have been written.
        /// </summary>
        public Int32    Exchanges    { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP client logger.
        /// </summary>
        /// <param name="Sink">Where the lines go, or the debug console.</param>
        /// <param name="LogBodies">Whether to write the bodies as well as the headers.</param>
        public OPCPClientLogger(Action<String>?  Sink        = null,
                                Boolean          LogBodies   = false)
        {

            this.sink       = Sink ?? (line => System.Diagnostics.Debug.WriteLine(line));
            this.LogBodies  = LogBodies;

        }

        #endregion


        #region Attach(Client)

        /// <summary>
        /// Listen to what a client sends and receives.
        /// </summary>
        /// <param name="Client">An OPCP client.</param>
        /// <returns>This logger, so that several clients can be attached in one expression.</returns>
        public OPCPClientLogger Attach(AOPCPHTTPClient Client)
        {

            Client.ClientRequestLogDelegate  += LogRequest;
            Client.ClientResponseLogDelegate += LogResponse;

            return this;

        }

        #endregion

        #region Detach(Client)

        /// <summary>
        /// Stop listening to a client.
        /// </summary>
        /// <param name="Client">An OPCP client.</param>
        public OPCPClientLogger Detach(AOPCPHTTPClient Client)
        {

            Client.ClientRequestLogDelegate  -= LogRequest;
            Client.ClientResponseLogDelegate -= LogResponse;

            return this;

        }

        #endregion


        #region (static) Redact(Text)

        /// <summary>
        /// Take the credentials out of an HTTP protocol data unit.
        /// </summary>
        /// <param name="Text">A request or a response, as text.</param>
        /// <remarks>
        /// By name rather than by shape: a bearer token and a signing secret look like any other
        /// long string, so what is elided is what the protocol calls a secret. Anything a future
        /// version of OPCP calls one has to be added here - which is why bodies stay off unless
        /// somebody asks for them.
        /// </remarks>
        public static String Redact(String Text)
        {

            if (Text.IsNullOrEmpty())
                return "";

            var text = authorization.Replace(Text, match => $"{match.Groups["name"].Value}{match.Groups["scheme"].Value} {Redacted}");

            text     = jsonSecrets.  Replace(text, match => $"\"{match.Groups["name"].Value}\": \"{Redacted}\"");

            text     = formSecrets.  Replace(text, match => $"{match.Groups["name"].Value}={Redacted}");

            return text;

        }

        #endregion


        #region (private) LogRequest / LogResponse

        private Task LogRequest(DateTimeOffset  Timestamp,
                                IHTTPClient     HTTPClient,
                                HTTPRequest     Request)
        {

            Exchanges++;

            Write($"{Timestamp.ToISO8601(false)} >>> {Request.HTTPMethod} {Request.Path}",
                  LogBodies
                      ? Request.EntirePDU
                      : Request.RawHTTPHeader);

            return Task.CompletedTask;

        }

        private Task LogResponse(DateTimeOffset  Timestamp,
                                 IHTTPClient     HTTPClient,
                                 HTTPRequest     Request,
                                 HTTPResponse    Response)
        {

            Write($"{Timestamp.ToISO8601(false)} <<< {Response.HTTPStatusCode.Code} {Response.HTTPStatusCode.Name} " +
                  $"({Request.HTTPMethod} {Request.Path})",
                  LogBodies
                      ? Response.EntirePDU
                      : Response.RawHTTPHeader);

            return Task.CompletedTask;

        }

        #endregion

        #region (private) Write(Summary, PDU)

        private void Write(String  Summary,
                           String  PDU)
        {
            try
            {
                sink($"{Summary}{Environment.NewLine}{Redact(PDU)}");
            }
            catch
            {
                // A logger that throws would take down the request it was watching, which is a
                // worse outcome than a missing log line.
            }
        }

        #endregion

    }

}
