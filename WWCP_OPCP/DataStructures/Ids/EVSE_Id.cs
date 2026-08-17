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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Extension methods for EVSE identifications.
    /// </summary>
    public static class EVSEIdExtensions
    {

        /// <summary>
        /// Indicates whether this EVSE identification is null or empty.
        /// </summary>
        /// <param name="EVSEId">An EVSE identification.</param>
        public static Boolean IsNullOrEmpty(this EVSE_Id? EVSEId)
            => !EVSEId.HasValue || EVSEId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this EVSE identification is NOT null or empty.
        /// </summary>
        /// <param name="EVSEId">An EVSE identification.</param>
        public static Boolean IsNotNullOrEmpty(this EVSE_Id? EVSEId)
            => EVSEId.HasValue && EVSEId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// An EVSE identification: one power outlet of one charging station.
    ///
    /// <code>
    /// &lt;EVSEID&gt; = &lt;Country Code&gt; &lt;S&gt; &lt;EVSE Operator ID&gt; &lt;S&gt; &lt;ID Type&gt; &lt;Power Outlet ID&gt;
    ///
    /// DE*ICE*E45B*78C     (ISO 15118-2:2014, Annex H.2.1)
    /// </code>
    ///
    /// It is the common name of the charging station's certificate, which is how a vehicle finds
    /// out what it has plugged into during the TLS handshake.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kept exactly as it was given, for the same reason a PCID is: it has to match a certificate
    /// subject byte for byte, and normalizing an identifier that must match would be a quiet way
    /// to break the match. Comparison is nevertheless case-insensitive.
    /// </para>
    /// <para>
    /// The enrollment interface writes the separator as <c>*</c> and the identifier document's own
    /// example of the neighbouring SECCID uses <c>-</c>; both are accepted, as is none at all. The
    /// same interface writes the alphanumeric groups as <c>\w</c>, which admits an underscore -
    /// the narrative rule beside it says ALPHA / DIGIT, and the stricter of the two wins, because
    /// an underscore is nothing ISO 15118 can carry.
    /// </para>
    /// </remarks>
    public readonly struct EVSE_Id : IId<EVSE_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// Country code, operator, the literal 'E', and the power outlet.
        /// </summary>
        private static readonly Regex pattern = new (@"^([A-Za-z]{2})[*-]?([A-Za-z0-9]{3})[*-]?[Ee]([A-Za-z0-9*-]{1,30})$",
                                                     RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this EVSE identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this EVSE identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the EVSE identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);


        /// <summary>
        /// The ISO 3166-1 alpha-2 country code.
        /// </summary>
        public String CountryCode
            => Group(1);

        /// <summary>
        /// The charge point operator, as listed by the eMI3 group.
        /// </summary>
        public String OperatorId
            => Group(2);

        /// <summary>
        /// The power outlet, including whatever separators it was written with.
        /// </summary>
        public String PowerOutletId
            => Group(3);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new EVSE identification based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of an EVSE identification.</param>
        private EVSE_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as an EVSE identification.
        /// </summary>
        /// <param name="Text">A text representation of an EVSE identification.</param>
        public static EVSE_Id Parse(String Text)
        {

            if (TryParse(Text, out var evseId))
                return evseId;

            throw new ArgumentException($"Invalid text representation of an EVSE identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as an EVSE identification.
        /// </summary>
        /// <param name="Text">A text representation of an EVSE identification.</param>
        public static EVSE_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var evseId))
                return evseId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out EVSEId)

        /// <summary>
        /// Try to parse the given text as an EVSE identification.
        /// </summary>
        /// <param name="Text">A text representation of an EVSE identification.</param>
        /// <param name="EVSEId">The parsed EVSE identification.</param>
        public static Boolean TryParse(String Text, out EVSE_Id EVSEId)
        {

            var text = Text.Trim();

            if (text.IsNotNullOrEmpty() && pattern.IsMatch(text))
            {
                EVSEId = new EVSE_Id(text);
                return true;
            }

            EVSEId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this EVSE identification.
        /// </summary>
        public EVSE_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region (private) Group(Number)

        /// <summary>
        /// One part of this identification, read back out of it.
        /// </summary>
        private String Group(Int32 Number)
        {

            if (InternalId.IsNullOrEmpty())
                return "";

            var match = pattern.Match(InternalId);

            return match.Success
                       ? match.Groups[Number].Value
                       : "";

        }

        #endregion


        #region Operator overloading

        #region Operator == (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (EVSE_Id EVSEId1,
                                           EVSE_Id EVSEId2)

            => EVSEId1.Equals(EVSEId2);

        #endregion

        #region Operator != (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (EVSE_Id EVSEId1,
                                           EVSE_Id EVSEId2)

            => !EVSEId1.Equals(EVSEId2);

        #endregion

        #region Operator <  (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (EVSE_Id EVSEId1,
                                          EVSE_Id EVSEId2)

            => EVSEId1.CompareTo(EVSEId2) < 0;

        #endregion

        #region Operator <= (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (EVSE_Id EVSEId1,
                                           EVSE_Id EVSEId2)

            => EVSEId1.CompareTo(EVSEId2) <= 0;

        #endregion

        #region Operator >  (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (EVSE_Id EVSEId1,
                                          EVSE_Id EVSEId2)

            => EVSEId1.CompareTo(EVSEId2) > 0;

        #endregion

        #region Operator >= (EVSEId1, EVSEId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EVSEId1">An EVSE identification.</param>
        /// <param name="EVSEId2">Another EVSE identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (EVSE_Id EVSEId1,
                                           EVSE_Id EVSEId2)

            => EVSEId1.CompareTo(EVSEId2) >= 0;

        #endregion

        #endregion

        #region IComparable<EVSE_Id> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two EVSE identifications.
        /// </summary>
        /// <param name="Object">An EVSE identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is EVSE_Id evseId
                   ? CompareTo(evseId)
                   : throw new ArgumentException("The given object is not an EVSE identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(EVSEId)

        /// <summary>
        /// Compares two EVSE identifications.
        /// </summary>
        /// <param name="EVSEId">An EVSE identification to compare with.</param>
        public Int32 CompareTo(EVSE_Id EVSEId)

            => String.Compare(InternalId,
                              EVSEId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<EVSE_Id> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two EVSE identifications for equality.
        /// </summary>
        /// <param name="Object">An EVSE identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is EVSE_Id evseId &&
                   Equals(evseId);

        #endregion

        #region Equals(EVSEId)

        /// <summary>
        /// Compares two EVSE identifications for equality.
        /// </summary>
        /// <param name="EVSEId">An EVSE identification to compare with.</param>
        public Boolean Equals(EVSE_Id EVSEId)

            => String.Equals(InternalId,
                             EVSEId.InternalId,
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
