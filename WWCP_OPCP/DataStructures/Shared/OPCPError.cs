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
    /// What an OPCP service says when it refuses: one or more human-readable messages, and the
    /// trace identification under which the operator's own logs recorded the attempt.
    ///
    /// Every OPCP service defines this shape identically, and three of them reach across files to
    /// borrow the certificate provisioning service's copy of it. This is that one type.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "Error": {
    ///   "title": "Error",
    ///   "type": "object",
    ///   "properties": {
    ///     "errorMessages": { "type": "array", "minItems": 1, "uniqueItems": true,
    ///                        "items": { "type": "string" } },
    ///     "traceId":       { "type": "string", "format": "uuid" }
    ///   }
    /// }
    /// </code>
    /// Neither property is required, which is why an error with nothing in it still parses.
    /// </remarks>
    public class OPCPError : IEquatable<OPCPError>
    {

        #region Properties

        /// <summary>
        /// What went wrong, in the operator's words. The specification's own examples range from
        /// a failed pattern match ("emaid : must match ...") to a plain sentence
        /// ("The contract for the given EMAID not found.").
        /// </summary>
        [Optional]
        public IEnumerable<String>  ErrorMessages    { get; }

        /// <summary>
        /// The identification under which the operator recorded this request. Quote it when
        /// asking them what happened.
        /// </summary>
        [Optional]
        public Trace_Id?            TraceId          { get; }


        /// <summary>
        /// The first error message, or an empty string when none was given.
        /// </summary>
        public String               FirstMessage
            => ErrorMessages.FirstOrDefault() ?? "";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new OPCP error.
        /// </summary>
        /// <param name="ErrorMessages">An optional enumeration of error messages.</param>
        /// <param name="TraceId">An optional trace identification.</param>
        public OPCPError(IEnumerable<String>?  ErrorMessages   = null,
                         Trace_Id?             TraceId         = null)
        {

            this.ErrorMessages  = ErrorMessages?.Where  (errorMessage => errorMessage.IsNotNullOrEmpty()).
                                                 Distinct().
                                                 ToArray() ?? [];

            this.TraceId        = TraceId;

            unchecked
            {
                hashCode = (this.ErrorMessages.CalcHashCode() * 3) ^
                           (this.TraceId?.     GetHashCode() ?? 0);
            }

        }

        #endregion


        #region (static) Create   (ErrorMessage, TraceId = null)

        /// <summary>
        /// Create a new OPCP error from a single message.
        /// </summary>
        /// <param name="ErrorMessage">An error message.</param>
        /// <param name="TraceId">An optional trace identification, otherwise a new one.</param>
        public static OPCPError Create(String     ErrorMessage,
                                       Trace_Id?  TraceId        = null)

            => new (
                   [ ErrorMessage ],
                   TraceId ?? Trace_Id.NewRandom()
               );

        #endregion

        #region (static) Parse    (JSON, CustomOPCPErrorParser = null)

        /// <summary>
        /// Parse the given JSON representation of an OPCP error.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="CustomOPCPErrorParser">An optional delegate to parse custom OPCP errors.</param>
        public static OPCPError Parse(JObject                                  JSON,
                                      CustomJObjectParserDelegate<OPCPError>?  CustomOPCPErrorParser   = null)
        {

            if (TryParse(JSON, out var opcpError, out var errorResponse, CustomOPCPErrorParser))
                return opcpError;

            throw new ArgumentException($"The given JSON representation of an OPCP error is invalid: {errorResponse}",
                                        nameof(JSON));

        }

        #endregion

        #region (static) TryParse (JSON, out OPCPError, out ErrorResponse, CustomOPCPErrorParser = null)

        /// <summary>
        /// Try to parse the given JSON representation of an OPCP error.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="OPCPError">The parsed OPCP error.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomOPCPErrorParser">An optional delegate to parse custom OPCP errors.</param>
        public static Boolean TryParse(JObject                                  JSON,
                                       [NotNullWhen(true)]  out OPCPError?      OPCPError,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<OPCPError>?  CustomOPCPErrorParser   = null)
        {

            try
            {

                OPCPError = null;

                if (JSON is null)
                {
                    ErrorResponse = "The given JSON object must not be null!";
                    return false;
                }

                #region ErrorMessages    [optional]

                if (JSON.ParseOptionalHashSet("errorMessages",
                                              "error messages",
                                              text => text,
                                              out HashSet<String> ErrorMessages,
                                              out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region TraceId          [optional]

                if (JSON.ParseOptional("traceId",
                                       "trace identification",
                                       Trace_Id.TryParse,
                                       out Trace_Id? TraceId,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion


                OPCPError = new OPCPError(
                                ErrorMessages,
                                TraceId
                            );

                if (CustomOPCPErrorParser is not null)
                    OPCPError = CustomOPCPErrorParser(JSON, OPCPError);

                return true;

            }
            catch (Exception e)
            {
                OPCPError      = null;
                ErrorResponse  = "The given JSON representation of an OPCP error is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomOPCPErrorSerializer = null)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomOPCPErrorSerializer">A delegate to serialize custom OPCP errors.</param>
        public JObject ToJSON(CustomJObjectSerializerDelegate<OPCPError>? CustomOPCPErrorSerializer = null)
        {

            var json = JSONObject.Create(

                                 ErrorMessages.Any()
                                     ? new JProperty("errorMessages",  new JArray(ErrorMessages))
                                     : null,

                                 TraceId.HasValue
                                     ? new JProperty("traceId",        TraceId.Value.ToString())
                                     : null

                       );

            return CustomOPCPErrorSerializer is not null
                       ? CustomOPCPErrorSerializer(this, json)
                       : json;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this OPCP error.
        /// </summary>
        public OPCPError Clone()

            => new (
                   ErrorMessages.Select(errorMessage => errorMessage.CloneString()).ToArray(),
                   TraceId?.Clone()
               );

        #endregion


        #region Operator overloading

        #region Operator == (OPCPError1, OPCPError2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPError1">An OPCP error.</param>
        /// <param name="OPCPError2">Another OPCP error.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (OPCPError? OPCPError1,
                                           OPCPError? OPCPError2)
        {

            if (ReferenceEquals(OPCPError1, OPCPError2))
                return true;

            if (OPCPError1 is null || OPCPError2 is null)
                return false;

            return OPCPError1.Equals(OPCPError2);

        }

        #endregion

        #region Operator != (OPCPError1, OPCPError2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPError1">An OPCP error.</param>
        /// <param name="OPCPError2">Another OPCP error.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (OPCPError? OPCPError1,
                                           OPCPError? OPCPError2)

            => !(OPCPError1 == OPCPError2);

        #endregion

        #endregion

        #region IEquatable<OPCPError> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two OPCP errors for equality.
        /// </summary>
        /// <param name="Object">An OPCP error to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is OPCPError opcpError &&
                   Equals(opcpError);

        #endregion

        #region Equals(OPCPError)

        /// <summary>
        /// Compares two OPCP errors for equality.
        /// </summary>
        /// <param name="OPCPError">An OPCP error to compare with.</param>
        public Boolean Equals(OPCPError? OPCPError)

            => OPCPError is not null &&

               Nullable.Equals(TraceId, OPCPError.TraceId) &&

               ErrorMessages.Count().Equals(OPCPError.ErrorMessages.Count()) &&
               ErrorMessages.All(OPCPError.ErrorMessages.Contains);

        #endregion

        #endregion

        #region (override) GetHashCode()

        private readonly Int32 hashCode;

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => hashCode;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => String.Concat(

                   ErrorMessages.Any()
                       ? ErrorMessages.AggregateWith("; ")
                       : "An unspecified OPCP error",

                   TraceId.HasValue
                       ? $" (trace {TraceId})"
                       : ""

               );

        #endregion

    }

}
