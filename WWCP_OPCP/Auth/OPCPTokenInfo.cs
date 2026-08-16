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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// What an OPCP access token says its holder may do.
    ///
    /// Beyond the usual JWT claims, an OPCP token carries three things the ecosystem's
    /// authorization turns on: the roles its holder acts in, the World Manufacturer Identifiers
    /// it may publish vehicles for, and the e-mobility provider identifications it may manage
    /// contracts for.
    /// </summary>
    /// <remarks>
    /// Those three are namespaced by the deployment's own URL - the example token of
    /// accessToken.v1.json spells them
    /// <c>https://eu.plugncharge-qa.hubject.com/role</c>, <c>.../pcid</c> and <c>.../emaid</c>.
    /// Since the namespace is whatever URL an ecosystem happens to live at, the claims are found
    /// by the last segment of their name rather than by a full match; a client that hard-coded
    /// one operator's URL would read nothing from another's token.
    ///
    /// Reading a token is not trusting it. <see cref="TryParse"/> decodes without verifying
    /// anything, which is all a client needs to know when its own token expires. A server must
    /// go through an <see cref="IAccessTokenValidator"/>, which checks the signature first.
    /// </remarks>
    public class OPCPTokenInfo
    {

        #region Properties

        /// <summary>
        /// The roles the holder acts in.
        /// </summary>
        public IEnumerable<OPCPRole>     Roles          { get; }

        /// <summary>
        /// The World Manufacturer Identifiers the holder may publish provisioning
        /// certificates for. From the 'pcid' claim.
        /// </summary>
        public IEnumerable<WMI>          WMIs           { get; }

        /// <summary>
        /// The e-mobility provider identifications the holder may manage contracts for.
        /// From the 'emaid' claim.
        /// </summary>
        public IEnumerable<Provider_Id>  ProviderIds    { get; }

        /// <summary>
        /// The name the ecosystem operator knows this client by.
        /// </summary>
        public String?                   ClientName     { get; }

        /// <summary>
        /// Who issued this token.
        /// </summary>
        public String?                   Issuer         { get; }

        /// <summary>
        /// Who this token is about.
        /// </summary>
        public String?                   Subject        { get; }

        /// <summary>
        /// The deployments this token is valid for.
        /// </summary>
        public IEnumerable<String>       Audiences      { get; }

        /// <summary>
        /// When this token was issued.
        /// </summary>
        public DateTimeOffset?           IssuedAt       { get; }

        /// <summary>
        /// When this token stops being valid.
        /// </summary>
        public DateTimeOffset?           ExpiresAt      { get; }

        /// <summary>
        /// The scopes this token opens.
        /// </summary>
        public IEnumerable<String>       Scopes         { get; }

        /// <summary>
        /// All claims of the token, for whatever this type does not surface.
        /// </summary>
        public JObject                   Claims         { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new description of an OPCP access token.
        /// </summary>
        /// <param name="Roles">The roles the holder acts in.</param>
        /// <param name="WMIs">The World Manufacturer Identifiers the holder may act for.</param>
        /// <param name="ProviderIds">The e-mobility provider identifications the holder may act for.</param>
        /// <param name="ClientName">An optional client name.</param>
        /// <param name="Issuer">An optional issuer.</param>
        /// <param name="Subject">An optional subject.</param>
        /// <param name="Audiences">An optional enumeration of audiences.</param>
        /// <param name="IssuedAt">An optional moment of issuance.</param>
        /// <param name="ExpiresAt">An optional moment of expiry.</param>
        /// <param name="Scopes">An optional enumeration of scopes.</param>
        /// <param name="Claims">The optional raw claims.</param>
        public OPCPTokenInfo(IEnumerable<OPCPRole>?     Roles         = null,
                             IEnumerable<WMI>?          WMIs          = null,
                             IEnumerable<Provider_Id>?  ProviderIds   = null,
                             String?                    ClientName    = null,
                             String?                    Issuer        = null,
                             String?                    Subject       = null,
                             IEnumerable<String>?       Audiences     = null,
                             DateTimeOffset?            IssuedAt      = null,
                             DateTimeOffset?            ExpiresAt     = null,
                             IEnumerable<String>?       Scopes        = null,
                             JObject?                   Claims        = null)
        {

            this.Roles        = Roles?.      Distinct().ToArray() ?? [];
            this.WMIs         = WMIs?.       Distinct().ToArray() ?? [];
            this.ProviderIds  = ProviderIds?.Distinct().ToArray() ?? [];
            this.ClientName   = ClientName;
            this.Issuer       = Issuer;
            this.Subject      = Subject;
            this.Audiences    = Audiences?.  Distinct().ToArray() ?? [];
            this.IssuedAt     = IssuedAt;
            this.ExpiresAt    = ExpiresAt;
            this.Scopes       = Scopes?.     Distinct().ToArray() ?? [];
            this.Claims       = Claims ?? [];

        }

        #endregion


        #region IsExpiredAt(Timestamp)

        /// <summary>
        /// Whether this token has expired. A token without an expiry never expires.
        /// </summary>
        /// <param name="Timestamp">A moment in time.</param>
        public Boolean IsExpiredAt(DateTimeOffset Timestamp)

            => ExpiresAt.HasValue && Timestamp >= ExpiresAt.Value;

        #endregion

        #region HasRole    (Role)

        /// <summary>
        /// Whether the holder acts in the given role.
        /// </summary>
        /// <param name="Role">A role.</param>
        public Boolean HasRole(OPCPRole Role)

            => Roles.Contains(Role);

        #endregion

        #region HasAnyRole (Roles)

        /// <summary>
        /// Whether the holder acts in any of the given roles.
        /// </summary>
        /// <param name="Roles">An enumeration of roles.</param>
        public Boolean HasAnyRole(params OPCPRole[] Roles)

            => Roles.Any(HasRole);

        #endregion

        #region MayActFor  (WMI | ProviderId | PCID | EMAId)

        /// <summary>
        /// Whether the holder may act for the given vehicle manufacturer.
        /// </summary>
        /// <param name="WMI">A World Manufacturer Identifier.</param>
        public Boolean MayActFor(WMI WMI)

            => WMIs.Contains(WMI);

        /// <summary>
        /// Whether the holder may act for the given e-mobility provider.
        /// </summary>
        /// <param name="ProviderId">An e-mobility provider identification.</param>
        public Boolean MayActFor(Provider_Id ProviderId)

            => ProviderIds.Contains(ProviderId);

        /// <summary>
        /// Whether the holder may act for the vehicle behind the given PCID, which is decided
        /// by the World Manufacturer Identifier it begins with.
        /// </summary>
        /// <param name="PCID">A PCID.</param>
        public Boolean MayActFor(PCID PCID)

            => MayActFor(PCID.WMI);

        /// <summary>
        /// Whether the holder may act for the contract behind the given EMAID, which is decided
        /// by the e-mobility provider identification it begins with.
        /// </summary>
        /// <param name="EMAId">An EMAID.</param>
        public Boolean MayActFor(EMA_Id EMAId)

            => MayActFor(EMAId.ProviderId);

        #endregion


        #region (static) TryParse(Token, out TokenInfo, out ErrorResponse)

        /// <summary>
        /// Decode the claims of a JSON Web Token, WITHOUT verifying its signature.
        ///
        /// This is what a client uses to notice that its own token is about to expire. A server
        /// deciding whether to honour a request must not use it: see
        /// <see cref="IAccessTokenValidator"/>.
        /// </summary>
        /// <param name="Token">A JSON Web Token.</param>
        /// <param name="TokenInfo">The decoded claims.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(String                                    Token,
                                       [NotNullWhen(true)]  out OPCPTokenInfo?   TokenInfo,
                                       [NotNullWhen(false)] out String?          ErrorResponse)
        {

            TokenInfo      = null;
            ErrorResponse  = null;

            var parts = (Token ?? "").Trim().Split('.');

            if (parts.Length != 3)
            {
                ErrorResponse = "A JSON Web Token must have three dot-separated parts!";
                return false;
            }

            if (!Base64URL.TryDecodeUTF8(parts[1], out var payload))
            {
                ErrorResponse = "The payload of the given token is not valid base64url!";
                return false;
            }

            JObject claims;

            try
            {
                claims = JObject.Parse(payload);
            }
            catch (Exception e)
            {
                ErrorResponse = "The payload of the given token is not valid JSON: " + e.Message;
                return false;
            }

            TokenInfo = FromClaims(claims);
            return true;

        }

        #endregion

        #region (static) FromClaims(Claims)

        /// <summary>
        /// Read an already decoded set of claims.
        /// </summary>
        /// <param name="Claims">The claims of a token.</param>
        public static OPCPTokenInfo FromClaims(JObject Claims)

            => new (
                   ReadNamespacedClaim(Claims, "role").
                       Select (OPCPRole.TryParse).
                       Where  (role => role.HasValue).
                       Select (role => role!.Value),

                   // The 'pcid' claim holds the manufacturer prefixes, not whole PCIDs - but a
                   // deployment that put a whole PCID there still means the manufacturer it
                   // begins with.
                   ReadNamespacedClaim(Claims, "pcid").
                       Select (ToWMI).
                       Where  (wmi => wmi.HasValue).
                       Select (wmi => wmi!.Value),

                   // Likewise the 'emaid' claim holds provider prefixes.
                   ReadNamespacedClaim(Claims, "emaid").
                       Select (ToProviderId).
                       Where  (providerId => providerId.HasValue).
                       Select (providerId => providerId!.Value),

                   ReadNamespacedClaim(Claims, "client_name").FirstOrDefault(),

                   Claims.Value<String>("iss"),
                   Claims.Value<String>("sub"),
                   ReadStringOrArray(Claims, "aud"),
                   ReadUnixTimestamp(Claims, "iat"),
                   ReadUnixTimestamp(Claims, "exp"),

                   (Claims.Value<String>("scope") ?? "").
                       Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),

                   Claims
               );

        #endregion


        #region (private, static) ReadNamespacedClaim(Claims, Name)

        /// <summary>
        /// Read a claim named by its last segment, e.g. 'role' out of
        /// "https://eu.plugncharge-qa.hubject.com/role".
        /// </summary>
        private static IEnumerable<String> ReadNamespacedClaim(JObject  Claims,
                                                              String   Name)
        {

            var suffix = "/" + Name;

            foreach (var property in Claims.Properties())
            {

                if (property.Name != Name &&
                   !property.Name.EndsWith(suffix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (property.Value is JArray array)
                {
                    foreach (var item in array)
                    {
                        var text = item.Value<String>();
                        if (text.IsNotNullOrEmpty())
                            yield return text;
                    }
                }

                else
                {
                    var text = property.Value.Value<String>();
                    if (text.IsNotNullOrEmpty())
                        yield return text;
                }

            }

        }

        #endregion

        #region (private, static) ReadStringOrArray(Claims, Name)

        /// <summary>
        /// Read a claim that RFC 7519 allows to be either one string or an array of them.
        /// </summary>
        private static IEnumerable<String> ReadStringOrArray(JObject  Claims,
                                                             String   Name)
        {

            var value = Claims[Name];

            if (value is JArray array)
                return array.Select(item => item.Value<String>()).
                             Where (text => text.IsNotNullOrEmpty()).
                             Select(text => text!);

            var single = value?.Value<String>();

            return single.IsNotNullOrEmpty()
                       ? [ single ]
                       : [];

        }

        #endregion

        #region (private, static) ReadUnixTimestamp(Claims, Name)

        private static DateTimeOffset? ReadUnixTimestamp(JObject  Claims,
                                                         String   Name)
        {

            var seconds = Claims[Name]?.Value<Int64>();

            return seconds.HasValue
                       ? DateTimeOffset.FromUnixTimeSeconds(seconds.Value)
                       : null;

        }

        #endregion

        #region (private, static) ToWMI / ToProviderId

        /// <summary>
        /// A manufacturer prefix, or the prefix of a whole PCID.
        /// </summary>
        private static WMI? ToWMI(String Text)

            => WMI. TryParse(Text) ??
               PCID.TryParse(Text)?.WMI;

        /// <summary>
        /// A provider prefix, or the prefix of a whole EMAID.
        /// </summary>
        private static Provider_Id? ToProviderId(String Text)

            => Provider_Id.TryParse(Text) ??
               EMA_Id.     TryParse(Text)?.ProviderId;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => String.Concat(

                   ClientName ?? Subject ?? "an anonymous client",

                   Roles.Any()
                       ? $" as [{Roles.AggregateWith(", ")}]"
                       : "",

                   WMIs.Any()
                       ? $", WMIs [{WMIs.AggregateWith(", ")}]"
                       : "",

                   ProviderIds.Any()
                       ? $", providers [{ProviderIds.AggregateWith(", ")}]"
                       : "",

                   ExpiresAt.HasValue
                       ? $", expiring {ExpiresAt.Value:yyyy-MM-dd HH:mm:ss} UTC"
                       : ""

               );

        #endregion

    }

}
