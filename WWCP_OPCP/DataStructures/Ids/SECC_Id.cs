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
    /// Extension methods for supply equipment communication controller identifications.
    /// </summary>
    public static class SECCIdExtensions
    {

        /// <summary>
        /// Indicates whether this SECC identification is null or empty.
        /// </summary>
        /// <param name="SECCId">A SECC identification.</param>
        public static Boolean IsNullOrEmpty(this SECC_Id? SECCId)
            => !SECCId.HasValue || SECCId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this SECC identification is NOT null or empty.
        /// </summary>
        /// <param name="SECCId">A SECC identification.</param>
        public static Boolean IsNotNullOrEmpty(this SECC_Id? SECCId)
            => SECCId.HasValue && SECCId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// A supply equipment communication controller identification: the box in a charging station
    /// that speaks ISO 15118, rather than one of the outlets it drives.
    ///
    /// <code>
    /// &lt;SECCID&gt; = &lt;Country Code&gt; &lt;S&gt; &lt;EVSE Operator ID&gt; &lt;S&gt; &lt;ID Type&gt; &lt;S&gt; &lt;ControllerID&gt; &lt;S&gt; &lt;Check Digit&gt;
    ///
    /// DE-ICE-S-00003C4D557878675645330967543476-2     (ISO 15118-20:2022)
    /// </code>
    ///
    /// It is what ISO 15118-20 puts in a charging station's certificate where ISO 15118-2 puts an
    /// EVSE identification, which is why enrollment accepts either.
    /// </summary>
    /// <remarks>
    /// Kept exactly as it was given, like every other identifier that has to match a certificate
    /// subject. The check digit is recognized only where a separator precedes it: without one,
    /// nothing distinguishes a trailing check digit from the last character of the controller
    /// identification, and guessing would silently shorten the identification.
    /// </remarks>
    public readonly struct SECC_Id : IId<SECC_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// Country code, operator, the literal 'S', the controller, and an optional check digit.
        /// </summary>
        private static readonly Regex pattern = new (@"^([A-Za-z]{2})[*-]?([A-Za-z0-9]{3})[*-]?[Ss][*-]?([A-Za-z0-9]+)(?:[*-]([A-Za-z0-9]))?$",
                                                     RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this SECC identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this SECC identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the SECC identification.
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
        /// The communication controller itself.
        /// </summary>
        public String ControllerId
            => Group(3);

        /// <summary>
        /// The check digit, when the identification was written with a separator before it.
        /// </summary>
        public Char? CheckDigit
        {
            get
            {
                var digit = Group(4);
                return digit.Length == 1
                           ? digit[0]
                           : null;
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new SECC identification based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a SECC identification.</param>
        private SECC_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a SECC identification.
        /// </summary>
        /// <param name="Text">A text representation of a SECC identification.</param>
        public static SECC_Id Parse(String Text)
        {

            if (TryParse(Text, out var seccId))
                return seccId;

            throw new ArgumentException($"Invalid text representation of a SECC identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a SECC identification.
        /// </summary>
        /// <param name="Text">A text representation of a SECC identification.</param>
        public static SECC_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var seccId))
                return seccId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out SECCId)

        /// <summary>
        /// Try to parse the given text as a SECC identification.
        /// </summary>
        /// <param name="Text">A text representation of a SECC identification.</param>
        /// <param name="SECCId">The parsed SECC identification.</param>
        public static Boolean TryParse(String Text, out SECC_Id SECCId)
        {

            var text = Text.Trim();

            if (text.IsNotNullOrEmpty() && pattern.IsMatch(text))
            {
                SECCId = new SECC_Id(text);
                return true;
            }

            SECCId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this SECC identification.
        /// </summary>
        public SECC_Id Clone()

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

        #region Operator == (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (SECC_Id SECCId1,
                                           SECC_Id SECCId2)

            => SECCId1.Equals(SECCId2);

        #endregion

        #region Operator != (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (SECC_Id SECCId1,
                                           SECC_Id SECCId2)

            => !SECCId1.Equals(SECCId2);

        #endregion

        #region Operator <  (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (SECC_Id SECCId1,
                                          SECC_Id SECCId2)

            => SECCId1.CompareTo(SECCId2) < 0;

        #endregion

        #region Operator <= (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (SECC_Id SECCId1,
                                           SECC_Id SECCId2)

            => SECCId1.CompareTo(SECCId2) <= 0;

        #endregion

        #region Operator >  (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (SECC_Id SECCId1,
                                          SECC_Id SECCId2)

            => SECCId1.CompareTo(SECCId2) > 0;

        #endregion

        #region Operator >= (SECCId1, SECCId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SECCId1">A SECC identification.</param>
        /// <param name="SECCId2">Another SECC identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (SECC_Id SECCId1,
                                           SECC_Id SECCId2)

            => SECCId1.CompareTo(SECCId2) >= 0;

        #endregion

        #endregion

        #region IComparable<SECC_Id> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two SECC identifications.
        /// </summary>
        /// <param name="Object">A SECC identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is SECC_Id seccId
                   ? CompareTo(seccId)
                   : throw new ArgumentException("The given object is not a SECC identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(SECCId)

        /// <summary>
        /// Compares two SECC identifications.
        /// </summary>
        /// <param name="SECCId">A SECC identification to compare with.</param>
        public Int32 CompareTo(SECC_Id SECCId)

            => String.Compare(InternalId,
                              SECCId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<SECC_Id> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two SECC identifications for equality.
        /// </summary>
        /// <param name="Object">A SECC identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is SECC_Id seccId &&
                   Equals(seccId);

        #endregion

        #region Equals(SECCId)

        /// <summary>
        /// Compares two SECC identifications for equality.
        /// </summary>
        /// <param name="SECCId">A SECC identification to compare with.</param>
        public Boolean Equals(SECC_Id SECCId)

            => String.Equals(InternalId,
                             SECCId.InternalId,
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
