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
    /// What an OPCP client got back: the HTTP outcome, how long it took, and either what was
    /// asked for or why it was refused.
    ///
    /// This is the non-generic form, for the operations that answer with a status and no body -
    /// deleting a provisioning certificate, marking a contract as the default for offline
    /// installation, probing whether a vehicle is known.
    /// </summary>
    public class OPCPResponse
    {

        #region Properties

        /// <summary>
        /// The HTTP status code the service answered with.
        /// </summary>
        public HTTPStatusCode    HTTPStatusCode     { get; }

        /// <summary>
        /// Why the request was refused, when it was.
        /// </summary>
        public OPCPError?        Error              { get; }

        /// <summary>
        /// When the request was sent.
        /// </summary>
        public DateTimeOffset    Timestamp          { get; }

        /// <summary>
        /// How long the request took.
        /// </summary>
        public TimeSpan          Runtime            { get; }

        /// <summary>
        /// The identification correlating this request with its logs on this side.
        /// Unrelated to the trace identification, which is the operator's own.
        /// </summary>
        public EventTracking_Id  EventTrackingId    { get; }

        /// <summary>
        /// The underlying HTTP response, for whatever this type does not surface.
        /// </summary>
        public HTTPResponse?     HTTPResponse       { get; }


        /// <summary>
        /// Whether the request succeeded.
        /// </summary>
        public Boolean           IsSuccess
            => Error is null;

        /// <summary>
        /// Whether the request was refused.
        /// </summary>
        public Boolean           HasError
            => Error is not null;

        /// <summary>
        /// The operator's trace identification for a refused request. Quote it when asking
        /// them what happened.
        /// </summary>
        public Trace_Id?         TraceId
            => Error?.TraceId;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP response.
        /// </summary>
        /// <param name="HTTPStatusCode">The HTTP status code.</param>
        /// <param name="Error">An optional error.</param>
        /// <param name="Timestamp">An optional timestamp of the request.</param>
        /// <param name="Runtime">An optional runtime of the request.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="HTTPResponse">An optional underlying HTTP response.</param>
        public OPCPResponse(HTTPStatusCode     HTTPStatusCode,
                            OPCPError?         Error             = null,
                            DateTimeOffset?    Timestamp         = null,
                            TimeSpan?          Runtime           = null,
                            EventTracking_Id?  EventTrackingId   = null,
                            HTTPResponse?      HTTPResponse      = null)
        {

            this.HTTPStatusCode   = HTTPStatusCode;
            this.Error            = Error;
            this.Timestamp        = Timestamp       ?? DateTimeOffset.UtcNow;
            this.Runtime          = Runtime         ?? TimeSpan.Zero;
            this.EventTrackingId  = EventTrackingId ?? EventTracking_Id.New;
            this.HTTPResponse     = HTTPResponse;

        }

        #endregion


        #region (static) Success(HTTPStatusCode = null, ...)

        /// <summary>
        /// The request succeeded.
        /// </summary>
        public static OPCPResponse Success(HTTPStatusCode?    HTTPStatusCode    = null,
                                           DateTimeOffset?    Timestamp         = null,
                                           TimeSpan?          Runtime           = null,
                                           EventTracking_Id?  EventTrackingId   = null,
                                           HTTPResponse?      HTTPResponse      = null)

            => new (HTTPStatusCode ?? org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPStatusCode.OK,
                    null,
                    Timestamp,
                    Runtime,
                    EventTrackingId,
                    HTTPResponse);

        #endregion

        #region (static) Failed (Error, HTTPStatusCode = null, ...)

        /// <summary>
        /// The request was refused.
        /// </summary>
        public static OPCPResponse Failed(OPCPError          Error,
                                          HTTPStatusCode?    HTTPStatusCode    = null,
                                          DateTimeOffset?    Timestamp         = null,
                                          TimeSpan?          Runtime           = null,
                                          EventTracking_Id?  EventTrackingId   = null,
                                          HTTPResponse?      HTTPResponse      = null)

            => new (HTTPStatusCode ?? org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPStatusCode.BadRequest,
                    Error,
                    Timestamp,
                    Runtime,
                    EventTrackingId,
                    HTTPResponse);

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => IsSuccess
                   ? $"{HTTPStatusCode.Code} after {Runtime.TotalMilliseconds:0} ms"
                   : $"{HTTPStatusCode.Code}: {Error}";

        #endregion

    }


    /// <summary>
    /// What an OPCP client got back, together with what it asked for.
    /// </summary>
    /// <typeparam name="T">The type of the payload.</typeparam>
    public class OPCPResponse<T> : OPCPResponse
    {

        #region Properties

        /// <summary>
        /// What was asked for, when the request succeeded.
        /// </summary>
        public T?  Data    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP response.
        /// </summary>
        /// <param name="HTTPStatusCode">The HTTP status code.</param>
        /// <param name="Data">The optional payload.</param>
        /// <param name="Error">An optional error.</param>
        /// <param name="Timestamp">An optional timestamp of the request.</param>
        /// <param name="Runtime">An optional runtime of the request.</param>
        /// <param name="EventTrackingId">An optional event tracking identification.</param>
        /// <param name="HTTPResponse">An optional underlying HTTP response.</param>
        public OPCPResponse(HTTPStatusCode     HTTPStatusCode,
                            T?                 Data              = default,
                            OPCPError?         Error             = null,
                            DateTimeOffset?    Timestamp         = null,
                            TimeSpan?          Runtime           = null,
                            EventTracking_Id?  EventTrackingId   = null,
                            HTTPResponse?      HTTPResponse      = null)

            : base(HTTPStatusCode,
                   Error,
                   Timestamp,
                   Runtime,
                   EventTrackingId,
                   HTTPResponse)

        {
            this.Data = Data;
        }

        #endregion


        #region (static) Success(Data, HTTPStatusCode = null, ...)

        /// <summary>
        /// The request succeeded and produced this.
        /// </summary>
        public static OPCPResponse<T> Success(T                  Data,
                                              HTTPStatusCode?    HTTPStatusCode    = null,
                                              DateTimeOffset?    Timestamp         = null,
                                              TimeSpan?          Runtime           = null,
                                              EventTracking_Id?  EventTrackingId   = null,
                                              HTTPResponse?      HTTPResponse      = null)

            => new (HTTPStatusCode ?? org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPStatusCode.OK,
                    Data,
                    null,
                    Timestamp,
                    Runtime,
                    EventTrackingId,
                    HTTPResponse);

        #endregion

        #region (static) Failed (Error, HTTPStatusCode = null, ...)

        /// <summary>
        /// The request was refused.
        /// </summary>
        public static new OPCPResponse<T> Failed(OPCPError          Error,
                                                 HTTPStatusCode?    HTTPStatusCode    = null,
                                                 DateTimeOffset?    Timestamp         = null,
                                                 TimeSpan?          Runtime           = null,
                                                 EventTracking_Id?  EventTrackingId   = null,
                                                 HTTPResponse?      HTTPResponse      = null)

            => new (HTTPStatusCode ?? org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPStatusCode.BadRequest,
                    default,
                    Error,
                    Timestamp,
                    Runtime,
                    EventTrackingId,
                    HTTPResponse);

        #endregion

        #region GetDataOrThrow()

        /// <summary>
        /// Return what was asked for, or throw with the operator's own words.
        ///
        /// For callers that would rather not branch on every response. Anything that has to keep
        /// running when a pool refuses should read <see cref="OPCPResponse.Error"/> instead.
        /// </summary>
        public T GetDataOrThrow()
        {

            if (Error is not null)
                throw new OPCPErrorException(this);

            if (Data is null)
                throw new OPCPErrorException(this, "The OPCP service answered successfully, but without any data!");

            return Data;

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => IsSuccess
                   ? $"{HTTPStatusCode.Code} {typeof(T).Name} after {Runtime.TotalMilliseconds:0} ms"
                   : $"{HTTPStatusCode.Code}: {Error}";

        #endregion

    }


    /// <summary>
    /// Thrown when a caller asked for the payload of a response that has none.
    /// </summary>
    public class OPCPErrorException : Exception
    {

        /// <summary>
        /// The response that carried the refusal.
        /// </summary>
        public OPCPResponse  Response    { get; }

        /// <summary>
        /// Create a new OPCP error exception.
        /// </summary>
        /// <param name="Response">The response that carried the refusal.</param>
        /// <param name="Message">An optional message, otherwise the operator's own.</param>
        public OPCPErrorException(OPCPResponse  Response,
                                  String?       Message    = null)

            : base(Message ?? Response.Error?.ToString() ?? "The OPCP request failed!")

        {
            this.Response = Response;
        }

    }

}
