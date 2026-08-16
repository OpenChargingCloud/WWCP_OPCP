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
    /// Extension methods for e-mobility provider identifications.
    /// </summary>
    public static class ProviderIdExtensions
    {

        /// <summary>
        /// Indicates whether this e-mobility provider identification is null or empty.
        /// </summary>
        /// <param name="ProviderId">An e-mobility provider identification.</param>
        public static Boolean IsNullOrEmpty(this Provider_Id? ProviderId)
            => !ProviderId.HasValue || ProviderId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this e-mobility provider identification is NOT null or empty.
        /// </summary>
        /// <param name="ProviderId">An e-mobility provider identification.</param>
        public static Boolean IsNotNullOrEmpty(this Provider_Id? ProviderId)
            => ProviderId.HasValue && ProviderId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The identification of an e-mobility provider: the country code and provider code that
    /// open every one of its EMAIDs.
    ///
    /// This is the unit in which an e-mobility provider is authorized. An access token names the
    /// provider identifications its holder may act for, and a request touching a contract whose
    /// EMAID begins with a different one is refused.
    /// </summary>
    public readonly struct Provider_Id : IId<Provider_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification, always in its normalized form.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// Two letters of country code followed by three alphanumerics of provider code.
        /// </summary>
        private static readonly Regex normalized = new (@"^[A-Z]{2}[0-9A-Z]{3}$",
                                                        RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this e-mobility provider identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this e-mobility provider identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the e-mobility provider identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);


        /// <summary>
        /// The ISO 3166-1 alpha-2 country code.
        /// </summary>
        public String CountryCode
            => InternalId?[..2] ?? "";

        /// <summary>
        /// The provider code, unique within the country.
        /// </summary>
        public String ProviderCode
            => InternalId?[2..5] ?? "";

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new e-mobility provider identification based on the given normalized text.
        /// </summary>
        /// <param name="Text">The normalized text representation of an e-mobility provider identification.</param>
        private Provider_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom()

        /// <summary>
        /// Create a new random e-mobility provider identification.
        /// </summary>
        public static Provider_Id NewRandom()
        {

            const String letters       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const String alphanumerics = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new (
                       new String([ letters      [Random.Shared.Next(letters.Length)],
                                    letters      [Random.Shared.Next(letters.Length)],
                                    alphanumerics[Random.Shared.Next(alphanumerics.Length)],
                                    alphanumerics[Random.Shared.Next(alphanumerics.Length)],
                                    alphanumerics[Random.Shared.Next(alphanumerics.Length)] ])
                   );

        }

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as an e-mobility provider identification.
        /// </summary>
        /// <param name="Text">A text representation of an e-mobility provider identification.</param>
        public static Provider_Id Parse(String Text)
        {

            if (TryParse(Text, out var providerId))
                return providerId;

            throw new ArgumentException($"Invalid text representation of an e-mobility provider identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as an e-mobility provider identification.
        /// </summary>
        /// <param name="Text">A text representation of an e-mobility provider identification.</param>
        public static Provider_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var providerId))
                return providerId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out ProviderId)

        /// <summary>
        /// Try to parse the given text as an e-mobility provider identification.
        /// </summary>
        /// <param name="Text">A text representation of an e-mobility provider identification, with or without a hyphen.</param>
        /// <param name="ProviderId">The parsed and normalized e-mobility provider identification.</param>
        public static Boolean TryParse(String Text, out Provider_Id ProviderId)
        {

            var text = Text.Trim().Replace("-", "").ToUpperInvariant();

            if (text.IsNotNullOrEmpty() && normalized.IsMatch(text))
            {
                ProviderId = new Provider_Id(text);
                return true;
            }

            ProviderId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this e-mobility provider identification.
        /// </summary>
        public Provider_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (Provider_Id ProviderId1,
                                           Provider_Id ProviderId2)

            => ProviderId1.Equals(ProviderId2);

        #endregion

        #region Operator != (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (Provider_Id ProviderId1,
                                           Provider_Id ProviderId2)

            => !ProviderId1.Equals(ProviderId2);

        #endregion

        #region Operator <  (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (Provider_Id ProviderId1,
                                          Provider_Id ProviderId2)

            => ProviderId1.CompareTo(ProviderId2) < 0;

        #endregion

        #region Operator <= (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (Provider_Id ProviderId1,
                                           Provider_Id ProviderId2)

            => ProviderId1.CompareTo(ProviderId2) <= 0;

        #endregion

        #region Operator >  (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (Provider_Id ProviderId1,
                                          Provider_Id ProviderId2)

            => ProviderId1.CompareTo(ProviderId2) > 0;

        #endregion

        #region Operator >= (ProviderId1, ProviderId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ProviderId1">An e-mobility provider identification.</param>
        /// <param name="ProviderId2">Another e-mobility provider identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (Provider_Id ProviderId1,
                                           Provider_Id ProviderId2)

            => ProviderId1.CompareTo(ProviderId2) >= 0;

        #endregion

        #endregion

        #region IComparable<ProviderId> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two e-mobility provider identifications.
        /// </summary>
        /// <param name="Object">An e-mobility provider identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is Provider_Id providerId
                   ? CompareTo(providerId)
                   : throw new ArgumentException("The given object is not an e-mobility provider identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(ProviderId)

        /// <summary>
        /// Compares two e-mobility provider identifications.
        /// </summary>
        /// <param name="ProviderId">An e-mobility provider identification to compare with.</param>
        public Int32 CompareTo(Provider_Id ProviderId)

            => String.Compare(InternalId,
                              ProviderId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<ProviderId> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two e-mobility provider identifications for equality.
        /// </summary>
        /// <param name="Object">An e-mobility provider identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is Provider_Id providerId &&
                   Equals(providerId);

        #endregion

        #region Equals(ProviderId)

        /// <summary>
        /// Compares two e-mobility provider identifications for equality.
        /// </summary>
        /// <param name="ProviderId">An e-mobility provider identification to compare with.</param>
        public Boolean Equals(Provider_Id ProviderId)

            => String.Equals(InternalId,
                             ProviderId.InternalId,
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
