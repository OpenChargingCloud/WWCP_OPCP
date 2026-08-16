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
    /// Extension methods for e-mobility authentication identifiers.
    /// </summary>
    public static class EMAIdExtensions
    {

        /// <summary>
        /// Indicates whether this EMAID is null or empty.
        /// </summary>
        /// <param name="EMAId">An EMAID.</param>
        public static Boolean IsNullOrEmpty(this EMA_Id? EMAId)
            => !EMAId.HasValue || EMAId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this EMAID is NOT null or empty.
        /// </summary>
        /// <param name="EMAId">An EMAID.</param>
        public static Boolean IsNotNullOrEmpty(this EMA_Id? EMAId)
            => EMAId.HasValue && EMAId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// An E-Mobility Authentication Identifier (EMAID), the identification of a charging contract.
    ///
    /// ISO 15118-2 leaves the written form flexible - hyphens between the groups are optional, as is
    /// the trailing check digit - and OPCP resolves that flexibility by normalizing: incoming EMAIDs
    /// are uppercased and stripped of their hyphens, because ISO 15118-2 can carry only 15 characters
    /// between vehicle and charging station. Everything stored, compared and sent by this library is
    /// that normalized form.
    ///
    /// The first five characters - country code and provider code - are also the unit of authorization:
    /// an e-mobility provider is granted access to exactly the EMAIDs beginning with its own prefixes.
    ///
    /// <code>
    /// &lt;EMAID&gt; = &lt;Country Code&gt; &lt;S&gt; &lt;Provider ID&gt; &lt;S&gt; &lt;eMA Instance&gt; &lt;S&gt; &lt;Check Digit&gt;
    ///
    /// normalized:  /[A-Z]{2}[\dA-Z]{3}[\dA-Z]{9}/i
    /// accepted:    /[a-z]{2}(-?)[\da-z]{3}\1[\da-z]{9}(\1[\da-z])?/i
    /// </code>
    /// </summary>
    /// <remarks>
    /// The check digit is preserved when given, but never computed or verified: OPCP nowhere requires
    /// it, and a wrong implementation of the DIN SPEC 91286 algorithm would be worse than none.
    /// </remarks>
    public readonly struct EMA_Id : IId<EMA_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification, always in its normalized form.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// The normalized form: two letters, three alphanumerics, nine alphanumerics
        /// and an optional check digit.
        /// </summary>
        private static readonly Regex normalized = new (@"^[A-Z]{2}[0-9A-Z]{3}[0-9A-Z]{9}[0-9A-Z]?$",
                                                        RegexOptions.Compiled);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this EMAID is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this EMAID is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the EMAID: 14 without a check digit, 15 with one.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);


        /// <summary>
        /// The ISO 3166-1 alpha-2 country code of the e-mobility provider.
        /// </summary>
        public String CountryCode
            => InternalId?[..2] ?? "";

        /// <summary>
        /// The provider code, unique within the country.
        /// </summary>
        public String ProviderCode
            => InternalId?[2..5] ?? "";

        /// <summary>
        /// The e-mobility provider owning this contract: country code and provider code together.
        /// This is the prefix an e-mobility provider is authorized for.
        /// </summary>
        public Provider_Id ProviderId
            => InternalId?.Length >= 5
                   ? Provider_Id.Parse(InternalId[..5])
                   : default;

        /// <summary>
        /// The e-mobility account instance, unique within the provider.
        /// </summary>
        public String InstanceId
            => InternalId?[5..14] ?? "";

        /// <summary>
        /// The check digit, when the EMAID was given with one.
        /// </summary>
        public Char? CheckDigit
            => InternalId?.Length == 15
                   ? InternalId[14]
                   : null;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new EMAID based on the given normalized text.
        /// </summary>
        /// <param name="Text">The normalized text representation of an EMAID.</param>
        private EMA_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom(ProviderId = null, WithCheckDigit = false)

        /// <summary>
        /// Create a new random EMAID.
        /// </summary>
        /// <param name="ProviderId">An optional e-mobility provider, otherwise a random one.</param>
        /// <param name="WithCheckDigit">Whether to append a (random, unverified) check digit.</param>
        public static EMA_Id NewRandom(Provider_Id?  ProviderId       = null,
                                       Boolean       WithCheckDigit   = false)

            => new ((ProviderId ?? Provider_Id.NewRandom()).ToString() +
                    RandomAlphanumerics(9) +
                    (WithCheckDigit ? RandomAlphanumerics(1) : ""));

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as an EMAID.
        /// </summary>
        /// <param name="Text">A text representation of an EMAID.</param>
        public static EMA_Id Parse(String Text)
        {

            if (TryParse(Text, out var emaId))
                return emaId;

            throw new ArgumentException($"Invalid text representation of an EMAID: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as an EMAID.
        /// </summary>
        /// <param name="Text">A text representation of an EMAID.</param>
        public static EMA_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var emaId))
                return emaId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out EMAId)

        /// <summary>
        /// Try to parse the given text as an EMAID, in any of the forms ISO 15118-2 permits.
        /// </summary>
        /// <param name="Text">A text representation of an EMAID.</param>
        /// <param name="EMAId">The parsed and normalized EMAID.</param>
        public static Boolean TryParse(String Text, out EMA_Id EMAId)
        {

            // Hyphens are the only separator ISO 15118-2 and OPCP allow, and they are
            // dropped rather than remembered: the ecosystem stores the compact form.
            var text = Text.Trim().Replace("-", "").ToUpperInvariant();

            if (text.IsNotNullOrEmpty() && normalized.IsMatch(text))
            {
                EMAId = new EMA_Id(text);
                return true;
            }

            EMAId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this EMAID.
        /// </summary>
        public EMA_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region (private, static) RandomAlphanumerics(Length)

        private static String RandomAlphanumerics(Byte Length)
        {

            const String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new String(Enumerable.Range(0, Length).
                                         Select(_ => alphabet[Random.Shared.Next(alphabet.Length)]).
                                         ToArray());

        }

        #endregion


        #region Operator overloading

        #region Operator == (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (EMA_Id EMAId1,
                                           EMA_Id EMAId2)

            => EMAId1.Equals(EMAId2);

        #endregion

        #region Operator != (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (EMA_Id EMAId1,
                                           EMA_Id EMAId2)

            => !EMAId1.Equals(EMAId2);

        #endregion

        #region Operator <  (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (EMA_Id EMAId1,
                                          EMA_Id EMAId2)

            => EMAId1.CompareTo(EMAId2) < 0;

        #endregion

        #region Operator <= (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (EMA_Id EMAId1,
                                           EMA_Id EMAId2)

            => EMAId1.CompareTo(EMAId2) <= 0;

        #endregion

        #region Operator >  (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (EMA_Id EMAId1,
                                          EMA_Id EMAId2)

            => EMAId1.CompareTo(EMAId2) > 0;

        #endregion

        #region Operator >= (EMAId1, EMAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="EMAId1">An EMAID.</param>
        /// <param name="EMAId2">Another EMAID.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (EMA_Id EMAId1,
                                           EMA_Id EMAId2)

            => EMAId1.CompareTo(EMAId2) >= 0;

        #endregion

        #endregion

        #region IComparable<EMAId> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two EMAIDs.
        /// </summary>
        /// <param name="Object">An EMAID to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is EMA_Id emaId
                   ? CompareTo(emaId)
                   : throw new ArgumentException("The given object is not an EMAID!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(EMAId)

        /// <summary>
        /// Compares two EMAIDs.
        /// </summary>
        /// <param name="EMAId">An EMAID to compare with.</param>
        public Int32 CompareTo(EMA_Id EMAId)

            => String.Compare(InternalId,
                              EMAId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<EMAId> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two EMAIDs for equality.
        /// </summary>
        /// <param name="Object">An EMAID to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is EMA_Id emaId &&
                   Equals(emaId);

        #endregion

        #region Equals(EMAId)

        /// <summary>
        /// Compares two EMAIDs for equality.
        /// </summary>
        /// <param name="EMAId">An EMAID to compare with.</param>
        public Boolean Equals(EMA_Id EMAId)

            => String.Equals(InternalId,
                             EMAId.InternalId,
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
