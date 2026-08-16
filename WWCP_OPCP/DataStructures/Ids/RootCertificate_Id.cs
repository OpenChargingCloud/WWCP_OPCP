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
    /// Extension methods for root certificate identifications.
    /// </summary>
    public static class RootCertificateIdExtensions
    {

        /// <summary>
        /// Indicates whether this root certificate identification is null or empty.
        /// </summary>
        /// <param name="RootCertificateId">A root certificate identification.</param>
        public static Boolean IsNullOrEmpty(this RootCertificate_Id? RootCertificateId)
            => !RootCertificateId.HasValue || RootCertificateId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this root certificate identification is NOT null or empty.
        /// </summary>
        /// <param name="RootCertificateId">A root certificate identification.</param>
        public static Boolean IsNotNullOrEmpty(this RootCertificate_Id? RootCertificateId)
            => RootCertificateId.HasValue && RootCertificateId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The identification a Root Certificate Pool assigns to a root CA certificate it stores.
    ///
    /// This is a UUID minted by the pool, not anything derived from the certificate: the same
    /// certificate re-uploaded is a new entry with a new identification.
    /// </summary>
    public readonly struct RootCertificate_Id : IId<RootCertificate_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification, in the canonical lowercase hyphenated form.
        /// </summary>
        private readonly String InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this root certificate identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this root certificate identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the root certificate identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new root certificate identification based on the given canonical text.
        /// </summary>
        /// <param name="Text">The canonical text representation of a root certificate identification.</param>
        private RootCertificate_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom()

        /// <summary>
        /// Create a new random root certificate identification.
        /// </summary>
        public static RootCertificate_Id NewRandom()

            => new (Guid.NewGuid().ToString("D"));

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a root certificate identification.
        /// </summary>
        /// <param name="Text">A text representation of a root certificate identification.</param>
        public static RootCertificate_Id Parse(String Text)
        {

            if (TryParse(Text, out var rootCertificateId))
                return rootCertificateId;

            throw new ArgumentException($"Invalid text representation of a root certificate identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a root certificate identification.
        /// </summary>
        /// <param name="Text">A text representation of a root certificate identification.</param>
        public static RootCertificate_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var rootCertificateId))
                return rootCertificateId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out RootCertificateId)

        /// <summary>
        /// Try to parse the given text as a root certificate identification.
        /// </summary>
        /// <param name="Text">A hyphenated UUID.</param>
        /// <param name="RootCertificateId">The parsed root certificate identification.</param>
        public static Boolean TryParse(String Text, out RootCertificate_Id RootCertificateId)
        {

            // "D" only: the specification's pattern is the hyphenated form, and accepting
            // braced or bare UUIDs here would let a shape through that the pool never emits.
            if (Guid.TryParseExact(Text.Trim(), "D", out var guid))
            {
                RootCertificateId = new RootCertificate_Id(guid.ToString("D"));
                return true;
            }

            RootCertificateId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this root certificate identification.
        /// </summary>
        public RootCertificate_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (RootCertificate_Id RootCertificateId1,
                                           RootCertificate_Id RootCertificateId2)

            => RootCertificateId1.Equals(RootCertificateId2);

        #endregion

        #region Operator != (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (RootCertificate_Id RootCertificateId1,
                                           RootCertificate_Id RootCertificateId2)

            => !RootCertificateId1.Equals(RootCertificateId2);

        #endregion

        #region Operator <  (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (RootCertificate_Id RootCertificateId1,
                                          RootCertificate_Id RootCertificateId2)

            => RootCertificateId1.CompareTo(RootCertificateId2) < 0;

        #endregion

        #region Operator <= (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (RootCertificate_Id RootCertificateId1,
                                           RootCertificate_Id RootCertificateId2)

            => RootCertificateId1.CompareTo(RootCertificateId2) <= 0;

        #endregion

        #region Operator >  (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (RootCertificate_Id RootCertificateId1,
                                          RootCertificate_Id RootCertificateId2)

            => RootCertificateId1.CompareTo(RootCertificateId2) > 0;

        #endregion

        #region Operator >= (RootCertificateId1, RootCertificateId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="RootCertificateId1">A root certificate identification.</param>
        /// <param name="RootCertificateId2">Another root certificate identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (RootCertificate_Id RootCertificateId1,
                                           RootCertificate_Id RootCertificateId2)

            => RootCertificateId1.CompareTo(RootCertificateId2) >= 0;

        #endregion

        #endregion

        #region IComparable<RootCertificateId> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two root certificate identifications.
        /// </summary>
        /// <param name="Object">A root certificate identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is RootCertificate_Id rootCertificateId
                   ? CompareTo(rootCertificateId)
                   : throw new ArgumentException("The given object is not a root certificate identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(RootCertificateId)

        /// <summary>
        /// Compares two root certificate identifications.
        /// </summary>
        /// <param name="RootCertificateId">A root certificate identification to compare with.</param>
        public Int32 CompareTo(RootCertificate_Id RootCertificateId)

            => String.Compare(InternalId,
                              RootCertificateId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<RootCertificateId> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two root certificate identifications for equality.
        /// </summary>
        /// <param name="Object">A root certificate identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is RootCertificate_Id rootCertificateId &&
                   Equals(rootCertificateId);

        #endregion

        #region Equals(RootCertificateId)

        /// <summary>
        /// Compares two root certificate identifications for equality.
        /// </summary>
        /// <param name="RootCertificateId">A root certificate identification to compare with.</param>
        public Boolean Equals(RootCertificate_Id RootCertificateId)

            => String.Equals(InternalId,
                             RootCertificateId.InternalId,
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
