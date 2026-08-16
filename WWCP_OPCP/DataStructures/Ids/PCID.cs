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
    /// Extension methods for provisioning certificate identifiers.
    /// </summary>
    public static class PCIDExtensions
    {

        /// <summary>
        /// Indicates whether this PCID is null or empty.
        /// </summary>
        /// <param name="PCID">A PCID.</param>
        public static Boolean IsNullOrEmpty(this PCID? PCID)
            => !PCID.HasValue || PCID.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this PCID is NOT null or empty.
        /// </summary>
        /// <param name="PCID">A PCID.</param>
        public static Boolean IsNotNullOrEmpty(this PCID? PCID)
            => PCID.HasValue && PCID.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// A Provisioning Certificate Identifier (PCID), the identification of one vehicle.
    ///
    /// <code>
    /// &lt;PCID&gt; = &lt;WMI&gt; &lt;OEM's own unique ID&gt; &lt;check digit&gt;
    ///
    /// ^[a-zA-Z0-9]{17,18}$   (VDE-AR-E 2802-100-1:2019-12)
    /// </code>
    ///
    /// The leading three characters are the manufacturer's World Manufacturer Identifier and
    /// decide who may write this vehicle's provisioning certificate.
    /// </summary>
    /// <remarks>
    /// Unlike the EMAID, a PCID is stored exactly as it was given. It is the Common Name of the
    /// OEM provisioning certificate, and case-folding an identifier that has to match a certificate
    /// subject byte for byte would be a quiet way to break that match. Comparison is nevertheless
    /// case-insensitive, so a lookup does not depend on which spelling arrived first.
    /// </remarks>
    public readonly struct PCID : IId<PCID>
    {

        #region Data

        /// <summary>
        /// The internal identification.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// 17 or 18 alphanumerics.
        /// </summary>
        private static readonly Regex pattern = new (@"^[a-zA-Z0-9]{17,18}$",
                                                     RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this PCID is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this PCID is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the PCID: 17 without a check digit, 18 with one.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);


        /// <summary>
        /// The World Manufacturer Identifier of the vehicle manufacturer.
        /// This is the prefix a vehicle manufacturer is authorized for.
        /// </summary>
        public WMI WMI
            => InternalId?.Length >= 3
                   ? WMI.Parse(InternalId[..3])
                   : default;

        /// <summary>
        /// The manufacturer's own unique identification of the vehicle.
        /// </summary>
        public String VehicleId
            => InternalId?[3..17] ?? "";

        /// <summary>
        /// The check digit, when the PCID was given with one.
        /// </summary>
        public Char? CheckDigit
            => InternalId?.Length == 18
                   ? InternalId[17]
                   : null;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new PCID based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a PCID.</param>
        private PCID(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom(WMI = null, WithCheckDigit = false)

        /// <summary>
        /// Create a new random PCID.
        /// </summary>
        /// <param name="WMI">An optional World Manufacturer Identifier, otherwise a random one.</param>
        /// <param name="WithCheckDigit">Whether to append a (random, unverified) check digit.</param>
        public static PCID NewRandom(WMI?     WMI              = null,
                                     Boolean  WithCheckDigit   = false)
        {

            const String alphanumerics = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new (
                       (WMI ?? opcp.WMI.NewRandom()).ToString() +
                       new String(Enumerable.Range(0, WithCheckDigit ? 15 : 14).
                                             Select(_ => alphanumerics[Random.Shared.Next(alphanumerics.Length)]).
                                             ToArray())
                   );

        }

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a PCID.
        /// </summary>
        /// <param name="Text">A text representation of a PCID.</param>
        public static PCID Parse(String Text)
        {

            if (TryParse(Text, out var pcid))
                return pcid;

            throw new ArgumentException($"Invalid text representation of a PCID: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a PCID.
        /// </summary>
        /// <param name="Text">A text representation of a PCID.</param>
        public static PCID? TryParse(String Text)
        {

            if (TryParse(Text, out var pcid))
                return pcid;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out PCID)

        /// <summary>
        /// Try to parse the given text as a PCID.
        /// </summary>
        /// <param name="Text">A text representation of a PCID.</param>
        /// <param name="PCID">The parsed PCID.</param>
        public static Boolean TryParse(String Text, out PCID PCID)
        {

            var text = Text.Trim();

            if (text.IsNotNullOrEmpty() && pattern.IsMatch(text))
            {
                PCID = new PCID(text);
                return true;
            }

            PCID = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this PCID.
        /// </summary>
        public PCID Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (PCID PCID1,
                                           PCID PCID2)

            => PCID1.Equals(PCID2);

        #endregion

        #region Operator != (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (PCID PCID1,
                                           PCID PCID2)

            => !PCID1.Equals(PCID2);

        #endregion

        #region Operator <  (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (PCID PCID1,
                                          PCID PCID2)

            => PCID1.CompareTo(PCID2) < 0;

        #endregion

        #region Operator <= (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (PCID PCID1,
                                           PCID PCID2)

            => PCID1.CompareTo(PCID2) <= 0;

        #endregion

        #region Operator >  (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (PCID PCID1,
                                          PCID PCID2)

            => PCID1.CompareTo(PCID2) > 0;

        #endregion

        #region Operator >= (PCID1, PCID2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PCID1">A PCID.</param>
        /// <param name="PCID2">Another PCID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (PCID PCID1,
                                           PCID PCID2)

            => PCID1.CompareTo(PCID2) >= 0;

        #endregion

        #endregion

        #region IComparable<PCID> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two PCIDs.
        /// </summary>
        /// <param name="Object">A PCID to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is PCID pcid
                   ? CompareTo(pcid)
                   : throw new ArgumentException("The given object is not a PCID!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(PCID)

        /// <summary>
        /// Compares two PCIDs.
        /// </summary>
        /// <param name="PCID">A PCID to compare with.</param>
        public Int32 CompareTo(PCID PCID)

            => String.Compare(InternalId,
                              PCID.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<PCID> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two PCIDs for equality.
        /// </summary>
        /// <param name="Object">A PCID to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is PCID pcid &&
                   Equals(pcid);

        #endregion

        #region Equals(PCID)

        /// <summary>
        /// Compares two PCIDs for equality.
        /// </summary>
        /// <param name="PCID">A PCID to compare with.</param>
        public Boolean Equals(PCID PCID)

            => String.Equals(InternalId,
                             PCID.InternalId,
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
