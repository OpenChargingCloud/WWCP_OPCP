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
    /// Extension methods for root certificate types.
    /// </summary>
    public static class RootCertificateTypeExtensions
    {

        /// <summary>
        /// Indicates whether this root certificate type is null or empty.
        /// </summary>
        /// <param name="RootCertificateType">A root certificate type.</param>
        public static Boolean IsNullOrEmpty(this RootCertificateType? RootCertificateType)
            => !RootCertificateType.HasValue || RootCertificateType.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this root certificate type is NOT null or empty.
        /// </summary>
        /// <param name="RootCertificateType">A root certificate type.</param>
        public static Boolean IsNotNullOrEmpty(this RootCertificateType? RootCertificateType)
            => RootCertificateType.HasValue && RootCertificateType.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// What a root CA certificate in the Root Certificate Pool is the anchor of.
    ///
    /// The Root Certificate Pool writes these uppercase and filters on them lowercase - the query
    /// parameter of getAllRootCerts enumerates 'mo', 'v2g' and 'oem' while the certificates it
    /// returns carry 'MO', 'V2G', 'OEM' or 'PE'. Both spellings mean one type here, and the
    /// uppercase form is what this library emits.
    /// </summary>
    public readonly struct RootCertificateType : IId,
                                                 IEquatable<RootCertificateType>,
                                                 IComparable<RootCertificateType>
    {

        #region Data

        private readonly static Dictionary<String, RootCertificateType>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                                   InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this root certificate type is null or empty.
        /// </summary>
        public readonly  Boolean                           IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this root certificate type is NOT null or empty.
        /// </summary>
        public readonly  Boolean                           IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the root certificate type.
        /// </summary>
        public readonly  UInt64                            Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// All registered root certificate types.
        /// </summary>
        public static    IEnumerable<RootCertificateType>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new root certificate type based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a root certificate type.</param>
        private RootCertificateType(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static RootCertificateType Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new RootCertificateType(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as a root certificate type.
        /// </summary>
        /// <param name="Text">A text representation of a root certificate type.</param>
        public static RootCertificateType Parse(String Text)
        {

            if (TryParse(Text, out var rootCertificateType))
                return rootCertificateType;

            throw new ArgumentException($"Invalid text representation of a root certificate type: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a root certificate type.
        /// </summary>
        /// <param name="Text">A text representation of a root certificate type.</param>
        public static RootCertificateType? TryParse(String Text)
        {

            if (TryParse(Text, out var rootCertificateType))
                return rootCertificateType;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out RootCertificateType)

        /// <summary>
        /// Try to parse the given text as a root certificate type.
        /// </summary>
        /// <param name="Text">A text representation of a root certificate type.</param>
        /// <param name="RootCertificateType">The parsed root certificate type.</param>
        public static Boolean TryParse(String Text, out RootCertificateType RootCertificateType)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                // A type this library does not know registers itself: the pool is free to
                // grow a new trust domain, and refusing to read the rest of its answer over
                // one unfamiliar word would be the wrong trade.
                if (!lookup.TryGetValue(Text, out RootCertificateType))
                    RootCertificateType = Register(Text);

                return true;

            }

            RootCertificateType = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this root certificate type.
        /// </summary>
        public RootCertificateType Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        /// <summary>
        /// A Mobility Operator root CA, anchoring contract certificates.
        /// </summary>
        public static RootCertificateType  MO     { get; }
            = Register("MO");

        /// <summary>
        /// A Vehicle-to-Grid root CA, anchoring the ISO 15118 PKI: charging station,
        /// contract provisioning and vehicle certificates.
        /// </summary>
        public static RootCertificateType  V2G    { get; }
            = Register("V2G");

        /// <summary>
        /// A vehicle manufacturer root CA, anchoring OEM provisioning certificates.
        /// </summary>
        public static RootCertificateType  OEM    { get; }
            = Register("OEM");

        /// <summary>
        /// A Provisioning Environment root CA. Accepted when writing a root certificate,
        /// but absent from the type filter of getAllRootCerts.
        /// </summary>
        public static RootCertificateType  PE     { get; }
            = Register("PE");

        #endregion


        #region Operator overloading

        #region Operator == (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (RootCertificateType RootCertificateType1,
                                           RootCertificateType RootCertificateType2)

            => RootCertificateType1.Equals(RootCertificateType2);

        #endregion

        #region Operator != (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (RootCertificateType RootCertificateType1,
                                           RootCertificateType RootCertificateType2)

            => !RootCertificateType1.Equals(RootCertificateType2);

        #endregion

        #region Operator <  (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (RootCertificateType RootCertificateType1,
                                          RootCertificateType RootCertificateType2)

            => RootCertificateType1.CompareTo(RootCertificateType2) < 0;

        #endregion

        #region Operator <= (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (RootCertificateType RootCertificateType1,
                                           RootCertificateType RootCertificateType2)

            => RootCertificateType1.CompareTo(RootCertificateType2) <= 0;

        #endregion

        #region Operator >  (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (RootCertificateType RootCertificateType1,
                                          RootCertificateType RootCertificateType2)

            => RootCertificateType1.CompareTo(RootCertificateType2) > 0;

        #endregion

        #region Operator >= (RootCertificateType1, RootCertificateType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateType1">A root certificate type.</param>
        /// <param name="RootCertificateType2">Another root certificate type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (RootCertificateType RootCertificateType1,
                                           RootCertificateType RootCertificateType2)

            => RootCertificateType1.CompareTo(RootCertificateType2) >= 0;

        #endregion

        #endregion

        #region IComparable<RootCertificateType> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two root certificate types.
        /// </summary>
        /// <param name="Object">A root certificate type to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is RootCertificateType rootCertificateType
                   ? CompareTo(rootCertificateType)
                   : throw new ArgumentException("The given object is not a root certificate type!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(RootCertificateType)

        /// <summary>
        /// Compares two root certificate types.
        /// </summary>
        /// <param name="RootCertificateType">A root certificate type to compare with.</param>
        public Int32 CompareTo(RootCertificateType RootCertificateType)

            => String.Compare(InternalId,
                              RootCertificateType.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<RootCertificateType> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two root certificate types for equality.
        /// </summary>
        /// <param name="Object">A root certificate type to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is RootCertificateType rootCertificateType &&
                   Equals(rootCertificateType);

        #endregion

        #region Equals(RootCertificateType)

        /// <summary>
        /// Compares two root certificate types for equality.
        /// </summary>
        /// <param name="RootCertificateType">A root certificate type to compare with.</param>
        public Boolean Equals(RootCertificateType RootCertificateType)

            => String.Equals(InternalId,
                             RootCertificateType.InternalId,
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
