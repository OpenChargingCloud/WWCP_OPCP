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
    /// Extension methods for signature algorithms.
    /// </summary>
    public static class SignatureAlgorithmExtensions
    {

        /// <summary>
        /// Indicates whether this signature algorithm is null or empty.
        /// </summary>
        /// <param name="SignatureAlgorithm">A signature algorithm.</param>
        public static Boolean IsNullOrEmpty(this SignatureAlgorithm? SignatureAlgorithm)
            => !SignatureAlgorithm.HasValue || SignatureAlgorithm.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this signature algorithm is NOT null or empty.
        /// </summary>
        /// <param name="SignatureAlgorithm">A signature algorithm.</param>
        public static Boolean IsNotNullOrEmpty(this SignatureAlgorithm? SignatureAlgorithm)
            => SignatureAlgorithm.HasValue && SignatureAlgorithm.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The signature algorithm of an ISO 15118 certificate, named by its curve.
    ///
    /// OPCP names three, in the root certificate pool and when downloading a CA chain from the
    /// enrollment service. secp256r1 is the default and the only one ISO 15118-2 uses; the other
    /// two belong to ISO 15118-20.
    /// </summary>
    public readonly struct SignatureAlgorithm : IId,
                                                IEquatable<SignatureAlgorithm>,
                                                IComparable<SignatureAlgorithm>
    {

        #region Data

        private readonly static Dictionary<String, SignatureAlgorithm>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                                  InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this signature algorithm is null or empty.
        /// </summary>
        public readonly  Boolean                          IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this signature algorithm is NOT null or empty.
        /// </summary>
        public readonly  Boolean                          IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the signature algorithm.
        /// </summary>
        public readonly  UInt64                           Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// All registered signature algorithms.
        /// </summary>
        public static    IEnumerable<SignatureAlgorithm>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new signature algorithm based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a signature algorithm.</param>
        private SignatureAlgorithm(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static SignatureAlgorithm Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new SignatureAlgorithm(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as a signature algorithm.
        /// </summary>
        /// <param name="Text">A text representation of a signature algorithm.</param>
        public static SignatureAlgorithm Parse(String Text)
        {

            if (TryParse(Text, out var signatureAlgorithm))
                return signatureAlgorithm;

            throw new ArgumentException($"Invalid text representation of a signature algorithm: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a signature algorithm.
        /// </summary>
        /// <param name="Text">A text representation of a signature algorithm.</param>
        public static SignatureAlgorithm? TryParse(String Text)
        {

            if (TryParse(Text, out var signatureAlgorithm))
                return signatureAlgorithm;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out SignatureAlgorithm)

        /// <summary>
        /// Try to parse the given text as a signature algorithm.
        /// </summary>
        /// <param name="Text">A text representation of a signature algorithm.</param>
        /// <param name="SignatureAlgorithm">The parsed signature algorithm.</param>
        public static Boolean TryParse(String Text, out SignatureAlgorithm SignatureAlgorithm)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                if (!lookup.TryGetValue(Text, out SignatureAlgorithm))
                    SignatureAlgorithm = Register(Text);

                return true;

            }

            SignatureAlgorithm = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this signature algorithm.
        /// </summary>
        public SignatureAlgorithm Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        /// <summary>
        /// NIST P-256, the default and the only curve ISO 15118-2 uses.
        /// </summary>
        public static SignatureAlgorithm  secp256r1    { get; }
            = Register("secp256r1");

        /// <summary>
        /// NIST P-521, one of the two ISO 15118-20 curves.
        /// </summary>
        public static SignatureAlgorithm  secp521r1    { get; }
            = Register("secp521r1");

        /// <summary>
        /// Ed448, the Edwards curve of ISO 15118-20. The one algorithm here that .NET
        /// cannot do on its own, and the reason BouncyCastle is a dependency.
        /// </summary>
        public static SignatureAlgorithm  ed448        { get; }
            = Register("ed448");

        #endregion


        #region Operator overloading

        #region Operator == (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (SignatureAlgorithm SignatureAlgorithm1,
                                           SignatureAlgorithm SignatureAlgorithm2)

            => SignatureAlgorithm1.Equals(SignatureAlgorithm2);

        #endregion

        #region Operator != (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (SignatureAlgorithm SignatureAlgorithm1,
                                           SignatureAlgorithm SignatureAlgorithm2)

            => !SignatureAlgorithm1.Equals(SignatureAlgorithm2);

        #endregion

        #region Operator <  (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (SignatureAlgorithm SignatureAlgorithm1,
                                          SignatureAlgorithm SignatureAlgorithm2)

            => SignatureAlgorithm1.CompareTo(SignatureAlgorithm2) < 0;

        #endregion

        #region Operator <= (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (SignatureAlgorithm SignatureAlgorithm1,
                                           SignatureAlgorithm SignatureAlgorithm2)

            => SignatureAlgorithm1.CompareTo(SignatureAlgorithm2) <= 0;

        #endregion

        #region Operator >  (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (SignatureAlgorithm SignatureAlgorithm1,
                                          SignatureAlgorithm SignatureAlgorithm2)

            => SignatureAlgorithm1.CompareTo(SignatureAlgorithm2) > 0;

        #endregion

        #region Operator >= (SignatureAlgorithm1, SignatureAlgorithm2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="SignatureAlgorithm1">A signature algorithm.</param>
        /// <param name="SignatureAlgorithm2">Another signature algorithm.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (SignatureAlgorithm SignatureAlgorithm1,
                                           SignatureAlgorithm SignatureAlgorithm2)

            => SignatureAlgorithm1.CompareTo(SignatureAlgorithm2) >= 0;

        #endregion

        #endregion

        #region IComparable<SignatureAlgorithm> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two signature algorithms.
        /// </summary>
        /// <param name="Object">A signature algorithm to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is SignatureAlgorithm signatureAlgorithm
                   ? CompareTo(signatureAlgorithm)
                   : throw new ArgumentException("The given object is not a signature algorithm!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(SignatureAlgorithm)

        /// <summary>
        /// Compares two signature algorithms.
        /// </summary>
        /// <param name="SignatureAlgorithm">A signature algorithm to compare with.</param>
        public Int32 CompareTo(SignatureAlgorithm SignatureAlgorithm)

            => String.Compare(InternalId,
                              SignatureAlgorithm.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<SignatureAlgorithm> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two signature algorithms for equality.
        /// </summary>
        /// <param name="Object">A signature algorithm to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is SignatureAlgorithm signatureAlgorithm &&
                   Equals(signatureAlgorithm);

        #endregion

        #region Equals(SignatureAlgorithm)

        /// <summary>
        /// Compares two signature algorithms for equality.
        /// </summary>
        /// <param name="SignatureAlgorithm">A signature algorithm to compare with.</param>
        public Boolean Equals(SignatureAlgorithm SignatureAlgorithm)

            => String.Equals(InternalId,
                             SignatureAlgorithm.InternalId,
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
