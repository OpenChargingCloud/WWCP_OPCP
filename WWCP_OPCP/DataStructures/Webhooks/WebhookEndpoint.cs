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
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Where a partner wants to be told when something happens, and which somethings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The specification has three shapes of this - one to create, one to update, one to return -
    /// which carry the same fields and differ in which they insist on and in the four the service
    /// fills in itself. One type serves all three.
    /// </para>
    /// <code>
    /// "EndpointResponse": {
    ///   "required": [ "id", "created", "enabledEvents", "url" ],
    ///   "properties": {
    ///     "id":            { }, "url":         { }, "status":      { },
    ///     "apiVersion":    { }, "description": { }, "metadata":    { },
    ///     "created":       { "type": "integer" },   // seconds since the epoch
    ///     "secret":        { },                     // what the signature is made with
    ///     "providerIds":   [ ], "wmis":        [ ], // what this partner is allowed to hear about
    ///     "userRole":      { }, "userName":    { }
    ///   }
    /// }
    /// </code>
    /// <para>
    /// The scoping fields are the interesting ones: an endpoint registered by a mobility operator
    /// carries the provider identifications it may hear about, one registered by a vehicle
    /// manufacturer the manufacturer identifications - and the delivery service holds to them, so
    /// that a subscription cannot become a way of watching somebody else's cars.
    /// </para>
    /// </remarks>
    public class WebhookEndpoint
    {

        #region Data

        /// <summary>The value of <see cref="Status"/> that means events are delivered.</summary>
        public const String StatusEnabled   = "enabled";

        /// <summary>The value of <see cref="Status"/> that means they are not.</summary>
        public const String StatusDisabled  = "disabled";

        #endregion

        #region Properties

        /// <summary>
        /// The identification the service gave this endpoint.
        /// </summary>
        [Mandatory]
        public Webhook_Id                     Id                { get; }

        /// <summary>
        /// Where the events go.
        /// </summary>
        [Mandatory]
        public URL                            URL               { get; }

        /// <summary>
        /// Which events this partner asked for.
        /// </summary>
        [Mandatory]
        public IEnumerable<WebhookEventType>  EnabledEvents     { get; }

        /// <summary>
        /// When the endpoint was registered.
        /// </summary>
        [Mandatory]
        public DateTimeOffset                 Created           { get; }

        /// <summary>
        /// What the signature over each delivery is made with. The partner needs it to check that
        /// an event really came from this ecosystem.
        /// </summary>
        [Optional]
        public String?                        Secret            { get; }

        /// <summary>
        /// Whether events are delivered at all.
        /// </summary>
        [Optional]
        public String?                        Status            { get; }

        /// <summary>
        /// What the partner uses this endpoint for.
        /// </summary>
        [Optional]
        public String?                        Description       { get; }

        /// <summary>
        /// Which version events are rendered as.
        /// </summary>
        [Optional]
        public String?                        APIVersion        { get; }

        /// <summary>
        /// Whatever the partner attached to this endpoint.
        /// </summary>
        [Optional]
        public JObject?                       Metadata          { get; }

        /// <summary>
        /// The e-mobility providers this endpoint may hear about, for an endpoint a mobility
        /// operator registered.
        /// </summary>
        [Optional]
        public IEnumerable<Provider_Id>       ProviderIds       { get; }

        /// <summary>
        /// The vehicle manufacturers this endpoint may hear about, for an endpoint a manufacturer
        /// registered.
        /// </summary>
        [Optional]
        public IEnumerable<WMI>               WMIs              { get; }

        /// <summary>
        /// The role the endpoint was registered in.
        /// </summary>
        [Optional]
        public OPCPRole?                      UserRole          { get; }

        /// <summary>
        /// Who registered it.
        /// </summary>
        [Optional]
        public String?                        UserName          { get; }


        /// <summary>
        /// Whether this endpoint is receiving events. An endpoint that says nothing about its
        /// status is receiving them: the specification's own create example says "enabled", and
        /// registering an endpoint that is off by default would be a surprising thing to do.
        /// </summary>
        public Boolean                        IsEnabled
            => Status.IsNullOrEmpty() ||
               Status!.Equals(StatusEnabled, StringComparison.OrdinalIgnoreCase);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook endpoint.
        /// </summary>
        /// <param name="URL">Where the events go.</param>
        /// <param name="EnabledEvents">Which events this partner asked for.</param>
        /// <param name="Id">The identification the service gave it.</param>
        /// <param name="Created">When it was registered.</param>
        /// <param name="Secret">What the signature over each delivery is made with.</param>
        /// <param name="Status">Whether events are delivered at all.</param>
        /// <param name="Description">What the partner uses it for.</param>
        /// <param name="APIVersion">Which version events are rendered as.</param>
        /// <param name="Metadata">Whatever the partner attached to it.</param>
        /// <param name="ProviderIds">The e-mobility providers it may hear about.</param>
        /// <param name="WMIs">The vehicle manufacturers it may hear about.</param>
        /// <param name="UserRole">The role it was registered in.</param>
        /// <param name="UserName">Who registered it.</param>
        public WebhookEndpoint(URL                             URL,
                               IEnumerable<WebhookEventType>   EnabledEvents,
                               Webhook_Id?                     Id            = null,
                               DateTimeOffset?                 Created       = null,
                               String?                         Secret        = null,
                               String?                         Status        = null,
                               String?                         Description   = null,
                               String?                         APIVersion    = null,
                               JObject?                        Metadata      = null,
                               IEnumerable<Provider_Id>?       ProviderIds   = null,
                               IEnumerable<WMI>?               WMIs          = null,
                               OPCPRole?                       UserRole      = null,
                               String?                         UserName      = null)
        {

            this.URL            = URL;
            this.EnabledEvents  = EnabledEvents?.Distinct().ToArray() ?? [];
            this.Id             = Id      ?? Webhook_Id.NewRandom();
            this.Created        = Created ?? DateTimeOffset.UtcNow;
            this.Secret         = Secret;
            this.Status         = Status;
            this.Description    = Description;
            this.APIVersion     = APIVersion;
            this.Metadata       = Metadata;
            this.ProviderIds    = ProviderIds?.Distinct().ToArray() ?? [];
            this.WMIs           = WMIs?.       Distinct().ToArray() ?? [];
            this.UserRole       = UserRole;
            this.UserName       = UserName;

        }

        #endregion


        #region (static) NewSecret(Bytes = 32)

        /// <summary>
        /// A signing secret for a new endpoint.
        /// </summary>
        /// <param name="Bytes">How much entropy.</param>
        /// <remarks>
        /// From a cryptographic random source, because this one value is the whole of what stops
        /// a third party from sending a partner events that never happened.
        /// </remarks>
        public static String NewSecret(Int32 Bytes = 32)

            => Convert.ToHexString(RandomNumberGenerator.GetBytes(Bytes)).ToLowerInvariant();

        #endregion

        #region With(...)

        /// <summary>
        /// Return this endpoint with what a registration or an update settled.
        /// </summary>
        /// <param name="Id">The identification the service gave it.</param>
        /// <param name="Created">When it was registered.</param>
        /// <param name="Secret">What the signature over each delivery is made with.</param>
        /// <param name="ProviderIds">The e-mobility providers it may hear about.</param>
        /// <param name="WMIs">The vehicle manufacturers it may hear about.</param>
        /// <param name="UserRole">The role it was registered in.</param>
        /// <param name="UserName">Who registered it.</param>
        public WebhookEndpoint With(Webhook_Id?                Id            = null,
                                    DateTimeOffset?            Created       = null,
                                    String?                    Secret        = null,
                                    IEnumerable<Provider_Id>?  ProviderIds   = null,
                                    IEnumerable<WMI>?          WMIs          = null,
                                    OPCPRole?                  UserRole      = null,
                                    String?                    UserName      = null)

            => new (URL,
                    EnabledEvents,
                    Id          ?? this.Id,
                    Created     ?? this.Created,
                    Secret      ?? this.Secret,
                    Status,
                    Description,
                    APIVersion,
                    Metadata,
                    ProviderIds ?? this.ProviderIds,
                    WMIs        ?? this.WMIs,
                    UserRole    ?? this.UserRole,
                    UserName    ?? this.UserName);

        #endregion

        #region Wants(EventType)

        /// <summary>
        /// Whether this endpoint asked to hear about events of the given type.
        /// </summary>
        /// <param name="EventType">An event type.</param>
        public Boolean Wants(WebhookEventType EventType)

            => IsEnabled &&
               EnabledEvents.Contains(EventType);

        #endregion

        #region MayHearAbout(EMAId | PCID)

        /// <summary>
        /// Whether this endpoint is allowed to hear about the given contract.
        /// </summary>
        /// <param name="EMAId">A contract.</param>
        /// <remarks>
        /// An endpoint that names no providers hears about all of them - which is what an endpoint
        /// registered by somebody who is not a mobility operator does. Naming some is what narrows
        /// it, and is the whole point of the field.
        /// </remarks>
        public Boolean MayHearAbout(EMA_Id EMAId)

            => !ProviderIds.Any() ||
               ProviderIds.Contains(EMAId.ProviderId);

        /// <summary>
        /// Whether this endpoint is allowed to hear about the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Boolean MayHearAbout(PCID PCID)

            => !WMIs.Any() ||
               WMIs.Contains(PCID.WMI);

        #endregion


        #region (static) TryParse(JSON, out WebhookEndpoint, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of a webhook endpoint.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="WebhookEndpoint">The parsed endpoint.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                   JSON,
                                       [NotNullWhen(true)]  out WebhookEndpoint? WebhookEndpoint,
                                       [NotNullWhen(false)] out String?          ErrorResponse)
        {

            WebhookEndpoint  = null;
            ErrorResponse    = null;

            try
            {

                #region URL              [mandatory]

                var urlText = JSON.Value<String>("url");

                if (urlText.IsNullOrEmpty())
                {
                    ErrorResponse = "The 'url' is missing!";
                    return false;
                }

                var url = URL.TryParse(urlText!);

                if (!url.HasValue)
                {
                    ErrorResponse = $"'{urlText}' is not a valid URL!";
                    return false;
                }

                #endregion

                #region EnabledEvents    [mandatory, under either of the two names]

                // The management interface calls this 'enabledEvents' and its own responses have
                // been seen to call it 'events'. Both are read; the first is written.
                var eventsArray = JSON["enabledEvents"] as JArray
                                      ?? JSON["events"] as JArray;

                var enabledEvents = eventsArray?.
                                        Select(token => WebhookEventType.TryParse(token.Value<String>() ?? "")).
                                        Where (eventType => eventType.HasValue).
                                        Select(eventType => eventType!.Value).
                                        ToArray() ?? [];

                #endregion

                #region Created          [optional, seconds since the epoch]

                DateTimeOffset? created = null;

                var createdValue = JSON.Value<Int64?>("created");

                if (createdValue.HasValue)
                    created = DateTimeOffset.FromUnixTimeSeconds(createdValue.Value);

                #endregion


                WebhookEndpoint = new WebhookEndpoint(
                                      url.Value,
                                      enabledEvents,
                                      Webhook_Id.TryParse(JSON.Value<String>("id") ?? ""),
                                      created,
                                      JSON.Value<String>("secret"),
                                      JSON.Value<String>("status"),
                                      JSON.Value<String>("description"),
                                      JSON.Value<String>("apiVersion"),
                                      JSON["metadata"] as JObject,
                                      (JSON["providerIds"] as JArray)?.
                                          Select(token => Provider_Id.TryParse(token.Value<String>() ?? "")).
                                          Where (providerId => providerId.HasValue).
                                          Select(providerId => providerId!.Value).
                                          ToArray(),
                                      (JSON["wmis"] as JArray)?.
                                          Select(token => WMI.TryParse(token.Value<String>() ?? "")).
                                          Where (wmi => wmi.HasValue).
                                          Select(wmi => wmi!.Value).
                                          ToArray(),
                                      OPCPRole.TryParse(JSON.Value<String>("userRole") ?? ""),
                                      JSON.Value<String>("userName")
                                  );

                return true;

            }
            catch (Exception e)
            {
                WebhookEndpoint  = null;
                ErrorResponse    = "The given JSON representation of a webhook endpoint is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(WithSecret = true)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="WithSecret">
        /// Whether to include the signing secret. The specification returns it both when an
        /// endpoint is created and when one is read back, so this is true by default - but a
        /// deployment that would rather show it once has somewhere to say so.
        /// </param>
        public JObject ToJSON(Boolean WithSecret = true)

            => JSONObject.Create(

                   new JProperty("id",              Id. ToString()),
                   new JProperty("url",             URL.ToString()),
                   new JProperty("enabledEvents",   new JArray(EnabledEvents.Select(eventType => eventType.ToString()))),
                   new JProperty("created",         Created.ToUnixTimeSeconds()),

                   WithSecret && Secret.IsNotNullOrEmpty()
                       ? new JProperty("secret",    Secret)
                       : null,

                   Status.IsNotNullOrEmpty()
                       ? new JProperty("status",    Status)
                       : null,

                   Description.IsNotNullOrEmpty()
                       ? new JProperty("description",  Description)
                       : null,

                   APIVersion.IsNotNullOrEmpty()
                       ? new JProperty("apiVersion",   APIVersion)
                       : null,

                   Metadata is not null
                       ? new JProperty("metadata",     Metadata)
                       : null,

                   ProviderIds.Any()
                       ? new JProperty("providerIds",  new JArray(ProviderIds.Select(providerId => providerId.ToString())))
                       : null,

                   WMIs.Any()
                       ? new JProperty("wmis",         new JArray(WMIs.Select(wmi => wmi.ToString())))
                       : null,

                   UserRole.HasValue
                       ? new JProperty("userRole",     UserRole.Value.ToString())
                       : null,

                   UserName.IsNotNullOrEmpty()
                       ? new JProperty("userName",     UserName)
                       : null

               );

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{Id} -> {URL} ({EnabledEvents.Count()} event(s){(IsEnabled ? "" : ", disabled")})";

        #endregion

    }

}
