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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Extension methods for trace identifications.
    /// </summary>
    public static class TraceIdExtensions
    {

        /// <summary>
        /// Indicates whether this trace identification is null or empty.
        /// </summary>
        /// <param name="TraceId">A trace identification.</param>
        public static Boolean IsNullOrEmpty(this Trace_Id? TraceId)
            => !TraceId.HasValue || TraceId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this trace identification is NOT null or empty.
        /// </summary>
        /// <param name="TraceId">A trace identification.</param>
        public static Boolean IsNotNullOrEmpty(this Trace_Id? TraceId)
            => TraceId.HasValue && TraceId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The identification an OPCP service assigns to one failed request, so that a report of
    /// "it did not work" can be matched against what the operator's logs recorded.
    ///
    /// It appears in every error response and nowhere else.
    /// </summary>
    public readonly struct Trace_Id : IId<Trace_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification, in the canonical lowercase hyphenated form.
        /// </summary>
        private readonly String InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this trace identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this trace identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the trace identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new trace identification based on the given canonical text.
        /// </summary>
        /// <param name="Text">The canonical text representation of a trace identification.</param>
        private Trace_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom()

        /// <summary>
        /// Create a new random trace identification.
        /// </summary>
        public static Trace_Id NewRandom()

            => new (Guid.NewGuid().ToString("D"));

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a trace identification.
        /// </summary>
        /// <param name="Text">A text representation of a trace identification.</param>
        public static Trace_Id Parse(String Text)
        {

            if (TryParse(Text, out var traceId))
                return traceId;

            throw new ArgumentException($"Invalid text representation of a trace identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a trace identification.
        /// </summary>
        /// <param name="Text">A text representation of a trace identification.</param>
        public static Trace_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var traceId))
                return traceId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out TraceId)

        /// <summary>
        /// Try to parse the given text as a trace identification.
        /// </summary>
        /// <param name="Text">A hyphenated UUID.</param>
        /// <param name="TraceId">The parsed trace identification.</param>
        public static Boolean TryParse(String Text, out Trace_Id TraceId)
        {

            if (Guid.TryParseExact(Text.Trim(), "D", out var guid))
            {
                TraceId = new Trace_Id(guid.ToString("D"));
                return true;
            }

            TraceId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this trace identification.
        /// </summary>
        public Trace_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (Trace_Id TraceId1,
                                           Trace_Id TraceId2)

            => TraceId1.Equals(TraceId2);

        #endregion

        #region Operator != (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (Trace_Id TraceId1,
                                           Trace_Id TraceId2)

            => !TraceId1.Equals(TraceId2);

        #endregion

        #region Operator <  (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (Trace_Id TraceId1,
                                          Trace_Id TraceId2)

            => TraceId1.CompareTo(TraceId2) < 0;

        #endregion

        #region Operator <= (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (Trace_Id TraceId1,
                                           Trace_Id TraceId2)

            => TraceId1.CompareTo(TraceId2) <= 0;

        #endregion

        #region Operator >  (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (Trace_Id TraceId1,
                                          Trace_Id TraceId2)

            => TraceId1.CompareTo(TraceId2) > 0;

        #endregion

        #region Operator >= (TraceId1, TraceId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="TraceId1">A trace identification.</param>
        /// <param name="TraceId2">Another trace identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (Trace_Id TraceId1,
                                           Trace_Id TraceId2)

            => TraceId1.CompareTo(TraceId2) >= 0;

        #endregion

        #endregion

        #region IComparable<TraceId> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two trace identifications.
        /// </summary>
        /// <param name="Object">A trace identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is Trace_Id traceId
                   ? CompareTo(traceId)
                   : throw new ArgumentException("The given object is not a trace identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(TraceId)

        /// <summary>
        /// Compares two trace identifications.
        /// </summary>
        /// <param name="TraceId">A trace identification to compare with.</param>
        public Int32 CompareTo(Trace_Id TraceId)

            => String.Compare(InternalId,
                              TraceId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<TraceId> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two trace identifications for equality.
        /// </summary>
        /// <param name="Object">A trace identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is Trace_Id traceId &&
                   Equals(traceId);

        #endregion

        #region Equals(TraceId)

        /// <summary>
        /// Compares two trace identifications for equality.
        /// </summary>
        /// <param name="TraceId">A trace identification to compare with.</param>
        public Boolean Equals(Trace_Id TraceId)

            => String.Equals(InternalId,
                             TraceId.InternalId,
                             StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => InternalId?.ToLower().GetHashCode() ?? 0;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => InternalId ?? "";

        #endregion

    }

}
