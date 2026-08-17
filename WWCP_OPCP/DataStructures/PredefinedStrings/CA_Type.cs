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
    /// Extension methods for certification authority types.
    /// </summary>
    public static class CATypeExtensions
    {

        /// <summary>
        /// Indicates whether this certification authority type is null or empty.
        /// </summary>
        /// <param name="CAType">A certification authority type.</param>
        public static Boolean IsNullOrEmpty(this CA_Type? CAType)
            => !CAType.HasValue || CAType.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this certification authority type is NOT null or empty.
        /// </summary>
        /// <param name="CAType">A certification authority type.</param>
        public static Boolean IsNotNullOrEmpty(this CA_Type? CAType)
            => CAType.HasValue && CAType.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// Which authority of the V2G PKI an enrollment request is addressed to, and therefore what
    /// kind of certificate comes back.
    ///
    /// <code>
    /// cpo → a charging station certificate      common name: an EVSEID or a SECCID
    /// mo  → a contract certificate              common name: an EMAID
    /// oem → a provisioning certificate          common name: a PCID
    /// veh → a vehicle certificate (-20)         common name: a PCID
    /// cps → a contract signing certificate      no common name rule
    /// </code>
    ///
    /// Every one of them issues from a different Sub-CA 2 below the V2G root, which is why the
    /// authority is part of the path rather than something the request could get wrong.
    /// </summary>
    public readonly struct CA_Type : IId,
                                     IEquatable<CA_Type>,
                                     IComparable<CA_Type>
    {

        #region Data

        private readonly static Dictionary<String, CA_Type>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                       InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this certification authority type is null or empty.
        /// </summary>
        public readonly  Boolean               IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this certification authority type is NOT null or empty.
        /// </summary>
        public readonly  Boolean               IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the certification authority type.
        /// </summary>
        public readonly  UInt64                Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// Whether this authority issues certificates whose common name is a vehicle - which the
        /// two of them that do spell the same way.
        /// </summary>
        public readonly  Boolean               IssuesForVehicles
            => Equals(OEM) || Equals(VEH);

        /// <summary>
        /// All registered certification authority types.
        /// </summary>
        public static    IEnumerable<CA_Type>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new certification authority type based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a certification authority type.</param>
        private CA_Type(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static CA_Type Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new CA_Type(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as a certification authority type.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority type.</param>
        public static CA_Type Parse(String Text)
        {

            if (TryParse(Text, out var caType))
                return caType;

            throw new ArgumentException($"Invalid text representation of a certification authority type: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a certification authority type.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority type.</param>
        public static CA_Type? TryParse(String Text)
        {

            if (TryParse(Text, out var caType))
                return caType;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out CAType)

        /// <summary>
        /// Try to parse the given text as a certification authority type.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority type.</param>
        /// <param name="CAType">The parsed certification authority type.</param>
        /// <remarks>
        /// A type this library does not know registers itself, as everywhere else here. It buys
        /// nothing dangerous: an authority nobody has registered is one the enrollment service
        /// cannot find, and it says so.
        /// </remarks>
        public static Boolean TryParse(String Text, out CA_Type CAType)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                if (!lookup.TryGetValue(Text, out CAType))
                    CAType = Register(Text);

                return true;

            }

            CAType = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this certification authority type.
        /// </summary>
        public CA_Type Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        /// <summary>
        /// The charge point operator authority: charging station certificates, whose common name
        /// is an EVSEID or a SECCID.
        /// </summary>
        public static CA_Type  CPO   { get; }
            = Register("cpo");

        /// <summary>
        /// The mobility operator authority: contract certificates, whose common name is an EMAID.
        /// </summary>
        public static CA_Type  MO    { get; }
            = Register("mo");

        /// <summary>
        /// The vehicle manufacturer authority: provisioning certificates, whose common name is
        /// a PCID.
        /// </summary>
        public static CA_Type  OEM   { get; }
            = Register("oem");

        /// <summary>
        /// The vehicle authority of ISO 15118-20, which issues against a PCID like the
        /// manufacturer authority does.
        /// </summary>
        public static CA_Type  VEH   { get; }
            = Register("veh");

        /// <summary>
        /// The contract provisioning authority: the certificates a provisioning service signs
        /// contract data with. The specification states no common name rule for these.
        /// </summary>
        public static CA_Type  CPS   { get; }
            = Register("cps");

        #endregion


        #region Operator overloading

        #region Operator == (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (CA_Type CAType1,
                                           CA_Type CAType2)

            => CAType1.Equals(CAType2);

        #endregion

        #region Operator != (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (CA_Type CAType1,
                                           CA_Type CAType2)

            => !CAType1.Equals(CAType2);

        #endregion

        #region Operator <  (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (CA_Type CAType1,
                                          CA_Type CAType2)

            => CAType1.CompareTo(CAType2) < 0;

        #endregion

        #region Operator <= (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (CA_Type CAType1,
                                           CA_Type CAType2)

            => CAType1.CompareTo(CAType2) <= 0;

        #endregion

        #region Operator >  (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (CA_Type CAType1,
                                          CA_Type CAType2)

            => CAType1.CompareTo(CAType2) > 0;

        #endregion

        #region Operator >= (CAType1, CAType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAType1">A certification authority type.</param>
        /// <param name="CAType2">Another certification authority type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (CA_Type CAType1,
                                           CA_Type CAType2)

            => CAType1.CompareTo(CAType2) >= 0;

        #endregion

        #endregion

        #region IComparable<CA_Type> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two certification authority types.
        /// </summary>
        /// <param name="Object">A certification authority type to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is CA_Type caType
                   ? CompareTo(caType)
                   : throw new ArgumentException("The given object is not a certification authority type!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(CAType)

        /// <summary>
        /// Compares two certification authority types.
        /// </summary>
        /// <param name="CAType">A certification authority type to compare with.</param>
        public Int32 CompareTo(CA_Type CAType)

            => String.Compare(InternalId,
                              CAType.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<CA_Type> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two certification authority types for equality.
        /// </summary>
        /// <param name="Object">A certification authority type to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is CA_Type caType &&
                   Equals(caType);

        #endregion

        #region Equals(CAType)

        /// <summary>
        /// Compares two certification authority types for equality.
        /// </summary>
        /// <param name="CAType">A certification authority type to compare with.</param>
        public Boolean Equals(CA_Type CAType)

            => String.Equals(InternalId,
                             CAType.InternalId,
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
