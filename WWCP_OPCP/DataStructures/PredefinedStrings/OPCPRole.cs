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
    /// Extension methods for OPCP roles.
    /// </summary>
    public static class OPCPRoleExtensions
    {

        /// <summary>
        /// Indicates whether this role is null or empty.
        /// </summary>
        /// <param name="OPCPRole">A role.</param>
        public static Boolean IsNullOrEmpty(this OPCPRole? OPCPRole)
            => !OPCPRole.HasValue || OPCPRole.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this role is NOT null or empty.
        /// </summary>
        /// <param name="OPCPRole">A role.</param>
        public static Boolean IsNotNullOrEmpty(this OPCPRole? OPCPRole)
            => OPCPRole.HasValue && OPCPRole.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// A role carried by an OPCP access token, deciding which operations its holder may call.
    ///
    /// The roles and rights table of the specification distinguishes five: vehicle manufacturer,
    /// charge point operator, certificate provisioning service, and the two kinds of e-mobility
    /// provider - one bringing its own PKI, one using the ecosystem's V2G PKI. Writing to the
    /// root certificate pool is reserved for an administrator of the ecosystem itself.
    /// </summary>
    /// <remarks>
    /// The actual claim values are chosen by whoever operates the ecosystem, not by the
    /// specification: the example token in accessToken.v1.json carries a manufacturer's own name
    /// alongside the roles below. Unknown roles therefore register themselves rather than failing
    /// to parse - a token is refused for the rights it lacks, never for a role nobody recognized.
    /// </remarks>
    public readonly struct OPCPRole : IId,
                                      IEquatable<OPCPRole>,
                                      IComparable<OPCPRole>
    {

        #region Data

        private readonly static Dictionary<String, OPCPRole>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                        InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this role is null or empty.
        /// </summary>
        public readonly  Boolean                IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this role is NOT null or empty.
        /// </summary>
        public readonly  Boolean                IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the role.
        /// </summary>
        public readonly  UInt64                 Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// Whether this is one of the two e-mobility provider roles.
        /// </summary>
        public readonly  Boolean                IsMobilityOperator
            => Equals(MO) || Equals(MO_ExternalPKI) || Equals(MO_V2GPKI);

        /// <summary>
        /// All registered roles.
        /// </summary>
        public static    IEnumerable<OPCPRole>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new role based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a role.</param>
        private OPCPRole(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static OPCPRole Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new OPCPRole(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as a role.
        /// </summary>
        /// <param name="Text">A text representation of a role.</param>
        public static OPCPRole Parse(String Text)
        {

            if (TryParse(Text, out var role))
                return role;

            throw new ArgumentException($"Invalid text representation of a role: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a role.
        /// </summary>
        /// <param name="Text">A text representation of a role.</param>
        public static OPCPRole? TryParse(String Text)
        {

            if (TryParse(Text, out var role))
                return role;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out OPCPRole)

        /// <summary>
        /// Try to parse the given text as a role.
        /// </summary>
        /// <param name="Text">A text representation of a role.</param>
        /// <param name="OPCPRole">The parsed role.</param>
        public static Boolean TryParse(String Text, out OPCPRole OPCPRole)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                if (!lookup.TryGetValue(Text, out OPCPRole))
                    OPCPRole = Register(Text);

                return true;

            }

            OPCPRole = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this role.
        /// </summary>
        public OPCPRole Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        /// <summary>
        /// A vehicle manufacturer, scoped to its own World Manufacturer Identifiers.
        /// </summary>
        public static OPCPRole  OEM              { get; }
            = Register("OEM");

        /// <summary>
        /// A charge point operator: the only role that may ask the contract certificate
        /// pool to answer a vehicle's certificate installation request.
        /// </summary>
        public static OPCPRole  CPO              { get; }
            = Register("CPO");

        /// <summary>
        /// A certificate provisioning service, writing signed contract data into the pool.
        /// </summary>
        public static OPCPRole  CPS              { get; }
            = Register("CPS");

        /// <summary>
        /// An e-mobility provider, scoped to its own provider identifications.
        /// </summary>
        public static OPCPRole  MO               { get; }
            = Register("MO");

        /// <summary>
        /// An e-mobility provider operating its own PKI: it signs contract data itself and
        /// has it counter-signed by the certificate provisioning service.
        /// </summary>
        public static OPCPRole  MO_ExternalPKI   { get; }
            = Register("MO_EXTERNAL_PKI");

        /// <summary>
        /// An e-mobility provider without its own PKI: the ecosystem's V2G mobility operator
        /// CA issues the contract certificate on its behalf.
        /// </summary>
        public static OPCPRole  MO_V2GPKI        { get; }
            = Register("MO_HUBJECT_PKI");

        /// <summary>
        /// An administrator of the ecosystem itself - the only role that may write to or
        /// delete from the root certificate pool.
        /// </summary>
        public static OPCPRole  Admin            { get; }
            = Register("Admin");

        #endregion


        #region Operator overloading

        #region Operator == (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (OPCPRole OPCPRole1,
                                           OPCPRole OPCPRole2)

            => OPCPRole1.Equals(OPCPRole2);

        #endregion

        #region Operator != (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (OPCPRole OPCPRole1,
                                           OPCPRole OPCPRole2)

            => !OPCPRole1.Equals(OPCPRole2);

        #endregion

        #region Operator <  (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (OPCPRole OPCPRole1,
                                          OPCPRole OPCPRole2)

            => OPCPRole1.CompareTo(OPCPRole2) < 0;

        #endregion

        #region Operator <= (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (OPCPRole OPCPRole1,
                                           OPCPRole OPCPRole2)

            => OPCPRole1.CompareTo(OPCPRole2) <= 0;

        #endregion

        #region Operator >  (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (OPCPRole OPCPRole1,
                                          OPCPRole OPCPRole2)

            => OPCPRole1.CompareTo(OPCPRole2) > 0;

        #endregion

        #region Operator >= (OPCPRole1, OPCPRole2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="OPCPRole1">A role.</param>
        /// <param name="OPCPRole2">Another role.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (OPCPRole OPCPRole1,
                                           OPCPRole OPCPRole2)

            => OPCPRole1.CompareTo(OPCPRole2) >= 0;

        #endregion

        #endregion

        #region IComparable<OPCPRole> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two roles.
        /// </summary>
        /// <param name="Object">A role to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is OPCPRole role
                   ? CompareTo(role)
                   : throw new ArgumentException("The given object is not a role!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(OPCPRole)

        /// <summary>
        /// Compares two roles.
        /// </summary>
        /// <param name="OPCPRole">A role to compare with.</param>
        public Int32 CompareTo(OPCPRole OPCPRole)

            => String.Compare(InternalId,
                              OPCPRole.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<OPCPRole> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two roles for equality.
        /// </summary>
        /// <param name="Object">A role to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is OPCPRole role &&
                   Equals(role);

        #endregion

        #region Equals(OPCPRole)

        /// <summary>
        /// Compares two roles for equality.
        /// </summary>
        /// <param name="OPCPRole">A role to compare with.</param>
        public Boolean Equals(OPCPRole OPCPRole)

            => String.Equals(InternalId,
                             OPCPRole.InternalId,
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
