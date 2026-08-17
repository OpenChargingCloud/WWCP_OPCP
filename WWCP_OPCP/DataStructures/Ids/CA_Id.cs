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
    /// Extension methods for certification authority identifications.
    /// </summary>
    public static class CAIdExtensions
    {

        /// <summary>
        /// Indicates whether this certification authority identification is null or empty.
        /// </summary>
        /// <param name="CAId">A certification authority identification.</param>
        public static Boolean IsNullOrEmpty(this CA_Id? CAId)
            => !CAId.HasValue || CAId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this certification authority identification is NOT null or empty.
        /// </summary>
        /// <param name="CAId">A certification authority identification.</param>
        public static Boolean IsNotNullOrEmpty(this CA_Id? CAId)
            => CAId.HasValue && CAId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// Which certification authority of a V2G PKI service an enrollment request is addressed to.
    ///
    /// <code>
    /// ^(\w+-)?(mo|cpo|oem|cps|veh)$
    ///
    /// cpo            the default charge point operator authority
    /// hubject-cpo    one operator's own
    /// </code>
    ///
    /// The specification lists the five defaults and, in the pattern beside them, allows any of
    /// them to be prefixed with the name of the operator running it - which is how one PKI service
    /// serves several. Both halves are kept here, because dropping the prefix would send an
    /// enrollment to the wrong authority and dropping the type would lose what kind of certificate
    /// was asked for.
    /// </summary>
    public readonly struct CA_Id : IId<CA_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification.
        /// </summary>
        private readonly String InternalId;

        /// <summary>
        /// An optional operator prefix, and one of the five authority types.
        /// </summary>
        private static readonly Regex pattern = new (@"^(?:([A-Za-z0-9_]+)-)?(mo|cpo|oem|cps|veh)$",
                                                     RegexOptions.Compiled | RegexOptions.IgnoreCase);

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this certification authority identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this certification authority identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the certification authority identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);


        /// <summary>
        /// Which kind of authority this is, and therefore what it issues.
        /// </summary>
        public CA_Type  Type
        {
            get
            {

                if (InternalId.IsNullOrEmpty())
                    return default;

                var match = pattern.Match(InternalId);

                return match.Success
                           ? CA_Type.Parse(match.Groups[2].Value.ToLowerInvariant())
                           : default;

            }
        }

        /// <summary>
        /// The operator running this authority, when the identification names one.
        /// </summary>
        public String?  OperatorPrefix
        {
            get
            {

                if (InternalId.IsNullOrEmpty())
                    return null;

                var match = pattern.Match(InternalId);

                return match.Success && match.Groups[1].Success
                           ? match.Groups[1].Value
                           : null;

            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new certification authority identification based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a certification authority identification.</param>
        private CA_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a certification authority identification.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority identification.</param>
        public static CA_Id Parse(String Text)
        {

            if (TryParse(Text, out var caId))
                return caId;

            throw new ArgumentException($"Invalid text representation of a certification authority identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) Parse    (CAType, OperatorPrefix = null)

        /// <summary>
        /// The identification of one authority of the given kind.
        /// </summary>
        /// <param name="CAType">The kind of authority.</param>
        /// <param name="OperatorPrefix">The operator running it, when it is not the default one.</param>
        public static CA_Id Parse(CA_Type  CAType,
                                  String?  OperatorPrefix   = null)

            => Parse(OperatorPrefix.IsNotNullOrEmpty()
                         ? $"{OperatorPrefix}-{CAType}"
                         : CAType.ToString());

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a certification authority identification.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority identification.</param>
        public static CA_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var caId))
                return caId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out CAId)

        /// <summary>
        /// Try to parse the given text as a certification authority identification.
        /// </summary>
        /// <param name="Text">A text representation of a certification authority identification.</param>
        /// <param name="CAId">The parsed certification authority identification.</param>
        public static Boolean TryParse(String Text, out CA_Id CAId)
        {

            var text = Text.Trim();

            if (text.IsNotNullOrEmpty() && pattern.IsMatch(text))
            {
                CAId = new CA_Id(text);
                return true;
            }

            CAId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this certification authority identification.
        /// </summary>
        public CA_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (CA_Id CAId1,
                                           CA_Id CAId2)

            => CAId1.Equals(CAId2);

        #endregion

        #region Operator != (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (CA_Id CAId1,
                                           CA_Id CAId2)

            => !CAId1.Equals(CAId2);

        #endregion

        #region Operator <  (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (CA_Id CAId1,
                                          CA_Id CAId2)

            => CAId1.CompareTo(CAId2) < 0;

        #endregion

        #region Operator <= (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (CA_Id CAId1,
                                           CA_Id CAId2)

            => CAId1.CompareTo(CAId2) <= 0;

        #endregion

        #region Operator >  (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (CA_Id CAId1,
                                          CA_Id CAId2)

            => CAId1.CompareTo(CAId2) > 0;

        #endregion

        #region Operator >= (CAId1, CAId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="CAId1">A certification authority identification.</param>
        /// <param name="CAId2">Another certification authority identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (CA_Id CAId1,
                                           CA_Id CAId2)

            => CAId1.CompareTo(CAId2) >= 0;

        #endregion

        #endregion

        #region IComparable<CA_Id> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two certification authority identifications.
        /// </summary>
        /// <param name="Object">A certification authority identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is CA_Id caId
                   ? CompareTo(caId)
                   : throw new ArgumentException("The given object is not a certification authority identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(CAId)

        /// <summary>
        /// Compares two certification authority identifications.
        /// </summary>
        /// <param name="CAId">A certification authority identification to compare with.</param>
        public Int32 CompareTo(CA_Id CAId)

            => String.Compare(InternalId,
                              CAId.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<CA_Id> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two certification authority identifications for equality.
        /// </summary>
        /// <param name="Object">A certification authority identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is CA_Id caId &&
                   Equals(caId);

        #endregion

        #region Equals(CAId)

        /// <summary>
        /// Compares two certification authority identifications for equality.
        /// </summary>
        /// <param name="CAId">A certification authority identification to compare with.</param>
        public Boolean Equals(CA_Id CAId)

            => String.Equals(InternalId,
                             CAId.InternalId,
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
