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
    /// Extension methods for World Manufacturer Identifiers.
    /// </summary>
    public static class WMIExtensions
    {

        /// <summary>
        /// Indicates whether this World Manufacturer Identifier is null or empty.
        /// </summary>
        /// <param name="WMI">A World Manufacturer Identifier.</param>
        public static Boolean IsNullOrEmpty(this WMI? WMI)
            => !WMI.HasValue || WMI.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this World Manufacturer Identifier is NOT null or empty.
        /// </summary>
        /// <param name="WMI">A World Manufacturer Identifier.</param>
        public static Boolean IsNotNullOrEmpty(this WMI? WMI)
            => WMI.HasValue && WMI.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// A World Manufacturer Identifier: the three characters that open every PCID of one
    /// vehicle manufacturer, and the unit in which a manufacturer is authorized.
    ///
    /// An access token names the WMIs its holder may act for. A manufacturer publishing or
    /// deleting a provisioning certificate for a PCID beginning with a WMI it was not granted
    /// is refused - which is what keeps one manufacturer out of another's vehicles.
    /// </summary>
    public readonly struct WMI : IId<WMI>
    {

        #region Data

        /// <summary>
        /// The internal identification, always uppercase.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// Three alphanumerics.
        /// </summary>
        private static readonly Regex normalized = new (@"^[0-9A-Z]{3}$",
                                                        RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this World Manufacturer Identifier is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this World Manufacturer Identifier is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the World Manufacturer Identifier.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new World Manufacturer Identifier based on the given normalized text.
        /// </summary>
        /// <param name="Text">The normalized text representation of a World Manufacturer Identifier.</param>
        private WMI(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom()

        /// <summary>
        /// Create a new random World Manufacturer Identifier.
        /// </summary>
        public static WMI NewRandom()
        {

            const String alphanumerics = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new (
                       new String([ alphanumerics[Random.Shared.Next(alphanumerics.Length)],
                                    alphanumerics[Random.Shared.Next(alphanumerics.Length)],
                                    alphanumerics[Random.Shared.Next(alphanumerics.Length)] ])
                   );

        }

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a World Manufacturer Identifier.
        /// </summary>
        /// <param name="Text">A text representation of a World Manufacturer Identifier.</param>
        public static WMI Parse(String Text)
        {

            if (TryParse(Text, out var wmi))
                return wmi;

            throw new ArgumentException($"Invalid text representation of a World Manufacturer Identifier: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a World Manufacturer Identifier.
        /// </summary>
        /// <param name="Text">A text representation of a World Manufacturer Identifier.</param>
        public static WMI? TryParse(String Text)
        {

            if (TryParse(Text, out var wmi))
                return wmi;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out WMI)

        /// <summary>
        /// Try to parse the given text as a World Manufacturer Identifier.
        /// </summary>
        /// <param name="Text">A text representation of a World Manufacturer Identifier.</param>
        /// <param name="WMI">The parsed and normalized World Manufacturer Identifier.</param>
        public static Boolean TryParse(String Text, out WMI WMI)
        {

            var text = Text.Trim().ToUpperInvariant();

            if (text.IsNotNullOrEmpty() && normalized.IsMatch(text))
            {
                WMI = new WMI(text);
                return true;
            }

            WMI = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this World Manufacturer Identifier.
        /// </summary>
        public WMI Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (WMI WMI1,
                                           WMI WMI2)

            => WMI1.Equals(WMI2);

        #endregion

        #region Operator != (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (WMI WMI1,
                                           WMI WMI2)

            => !WMI1.Equals(WMI2);

        #endregion

        #region Operator <  (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (WMI WMI1,
                                          WMI WMI2)

            => WMI1.CompareTo(WMI2) < 0;

        #endregion

        #region Operator <= (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (WMI WMI1,
                                           WMI WMI2)

            => WMI1.CompareTo(WMI2) <= 0;

        #endregion

        #region Operator >  (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (WMI WMI1,
                                          WMI WMI2)

            => WMI1.CompareTo(WMI2) > 0;

        #endregion

        #region Operator >= (WMI1, WMI2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WMI1">A World Manufacturer Identifier.</param>
        /// <param name="WMI2">Another World Manufacturer Identifier.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (WMI WMI1,
                                           WMI WMI2)

            => WMI1.CompareTo(WMI2) >= 0;

        #endregion

        #endregion

        #region IComparable<WMI> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two World Manufacturer Identifiers.
        /// </summary>
        /// <param name="Object">A World Manufacturer Identifier to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is WMI wmi
                   ? CompareTo(wmi)
                   : throw new ArgumentException("The given object is not a World Manufacturer Identifier!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(WMI)

        /// <summary>
        /// Compares two World Manufacturer Identifiers.
        /// </summary>
        /// <param name="WMI">A World Manufacturer Identifier to compare with.</param>
        public Int32 CompareTo(WMI WMI)

            => String.Compare(InternalId,
                              WMI.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<WMI> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two World Manufacturer Identifiers for equality.
        /// </summary>
        /// <param name="Object">A World Manufacturer Identifier to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is WMI wmi &&
                   Equals(wmi);

        #endregion

        #region Equals(WMI)

        /// <summary>
        /// Compares two World Manufacturer Identifiers for equality.
        /// </summary>
        /// <param name="WMI">A World Manufacturer Identifier to compare with.</param>
        public Boolean Equals(WMI WMI)

            => String.Equals(InternalId,
                             WMI.InternalId,
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
