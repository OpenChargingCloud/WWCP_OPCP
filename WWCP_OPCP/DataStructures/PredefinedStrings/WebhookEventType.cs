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
    /// Extension methods for webhook event types.
    /// </summary>
    public static class WebhookEventTypeExtensions
    {

        /// <summary>
        /// Indicates whether this event type is null or empty.
        /// </summary>
        /// <param name="WebhookEventType">An event type.</param>
        public static Boolean IsNullOrEmpty(this WebhookEventType? WebhookEventType)
            => !WebhookEventType.HasValue || WebhookEventType.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this event type is NOT null or empty.
        /// </summary>
        /// <param name="WebhookEventType">An event type.</param>
        public static Boolean IsNotNullOrEmpty(this WebhookEventType? WebhookEventType)
            => WebhookEventType.HasValue && WebhookEventType.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// Something that happened in the ecosystem and that a partner can ask to be told about.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The specification names these in three places and never the same list twice. The management
    /// interface enumerates fourteen, the narrative documentation adds <c>root.cert.revoked</c> and
    /// <c>mo.prov.cert.factory.reset</c>, and the payload document enumerates the second of those
    /// while omitting the <c>mo.prov.cert.updated.factory.reset</c> the other two carry - which the
    /// documentation marks deprecated in the same table it lists it in.
    /// </para>
    /// <para>
    /// All sixteen are here, because a partner who subscribes to an event one document knows about
    /// should not be turned away by a service that read a different one.
    /// </para>
    /// </remarks>
    public readonly struct WebhookEventType : IId,
                                              IEquatable<WebhookEventType>,
                                              IComparable<WebhookEventType>
    {

        #region Data

        private readonly static Dictionary<String, WebhookEventType>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                                InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this event type is null or empty.
        /// </summary>
        public readonly  Boolean                        IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this event type is NOT null or empty.
        /// </summary>
        public readonly  Boolean                        IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the event type.
        /// </summary>
        public readonly  UInt64                         Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// Whether this event is about a root certificate, and therefore carries the payload the
        /// specification describes for those rather than the one about vehicles and contracts.
        /// </summary>
        public readonly  Boolean                        IsRootCertificateEvent
            => InternalId?.StartsWith("root.", StringComparison.OrdinalIgnoreCase) == true;

        /// <summary>
        /// All registered event types.
        /// </summary>
        public static    IEnumerable<WebhookEventType>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new event type based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of an event type.</param>
        private WebhookEventType(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static WebhookEventType Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new WebhookEventType(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as an event type.
        /// </summary>
        /// <param name="Text">A text representation of an event type.</param>
        public static WebhookEventType Parse(String Text)
        {

            if (TryParse(Text, out var eventType))
                return eventType;

            throw new ArgumentException($"Invalid text representation of a webhook event type: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as an event type.
        /// </summary>
        /// <param name="Text">A text representation of an event type.</param>
        public static WebhookEventType? TryParse(String Text)
        {

            if (TryParse(Text, out var eventType))
                return eventType;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out WebhookEventType)

        /// <summary>
        /// Try to parse the given text as an event type.
        /// </summary>
        /// <param name="Text">A text representation of an event type.</param>
        /// <param name="WebhookEventType">The parsed event type.</param>
        /// <remarks>
        /// An event this library does not know registers itself. The ecosystem is expected to grow
        /// new events, and a partner subscribing to one that arrived after this library was
        /// written should get it rather than an error.
        /// </remarks>
        public static Boolean TryParse(String Text, out WebhookEventType WebhookEventType)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                if (!lookup.TryGetValue(Text, out WebhookEventType))
                    WebhookEventType = Register(Text);

                return true;

            }

            WebhookEventType = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this event type.
        /// </summary>
        public WebhookEventType Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        #region Root certificate pool

        /// <summary>
        /// A new root was admitted to the pool. A charge point operator reads this to find out
        /// that a new anchor has to reach its charging stations.
        /// </summary>
        public static WebhookEventType  RootCertificateAdded             { get; }
            = Register("root.cert.added");

        /// <summary>
        /// A root reached the end of its validity and left the pool. A natural phase-out rather
        /// than an emergency.
        /// </summary>
        public static WebhookEventType  RootCertificateExpired           { get; }
            = Register("root.cert.expired");

        /// <summary>
        /// A root was revoked and removed. Not an orderly phase-out, and the documentation says
        /// plainly that manual communication follows.
        /// </summary>
        /// <remarks>
        /// Absent from the management interface's own list of subscribable events, and present in
        /// both the narrative documentation and the payload document.
        /// </remarks>
        public static WebhookEventType  RootCertificateRevoked           { get; }
            = Register("root.cert.revoked");

        #endregion

        #region Provisioning certificates

        /// <summary>
        /// A vehicle's provisioning certificate was depublished, and its contracts went with it.
        /// </summary>
        public static WebhookEventType  ProvisioningCertificateDeleted   { get; }
            = Register("mo.prov.cert.deleted");

        /// <summary>
        /// A vehicle was republished with a different key pair - the workshop case. Every contract
        /// written against the old key is worthless and has been deleted.
        /// </summary>
        public static WebhookEventType  ProvisioningCertificateUpdated   { get; }
            = Register("mo.prov.cert.updated");

        /// <summary>
        /// A manufacturer deleted every contract of a vehicle: a factory reset, or a car that was
        /// sold. The operator is not to write new contracts for those EMAIDs.
        /// </summary>
        /// <remarks>
        /// Absent from the management interface's own list, and present in the payload document
        /// and the narrative documentation.
        /// </remarks>
        public static WebhookEventType  FactoryReset                     { get; }
            = Register("mo.prov.cert.factory.reset");

        /// <summary>
        /// The same thing under an older name, which the documentation marks deprecated in the
        /// very table that lists it.
        /// </summary>
        public static WebhookEventType  FactoryResetDeprecated           { get; }
            = Register("mo.prov.cert.updated.factory.reset");

        #endregion

        #region Contracts, as the mobility operator sees them

        /// <summary>
        /// The news of a new contract reached the manufacturer's backend.
        /// </summary>
        public static WebhookEventType  ContractCreatedSentToOEM         { get; }
            = Register("mo.contract.created.sent.to.oem");

        /// <summary>
        /// The news of an updated contract reached the manufacturer's backend.
        /// </summary>
        public static WebhookEventType  ContractUpdatedSentToOEM         { get; }
            = Register("mo.contract.updated.sent.to.oem");

        /// <summary>
        /// The news of a deleted contract reached the manufacturer's backend.
        /// </summary>
        public static WebhookEventType  ContractDeletedSentToOEM         { get; }
            = Register("mo.contract.deleted.sent.to.oem");

        /// <summary>
        /// A contract actually arrived in a car - collected by the manufacturer's backend, or
        /// installed through a charging station.
        /// </summary>
        public static WebhookEventType  ContractDeliveredToOEM           { get; }
            = Register("mo.contract.delivered.to.oem");

        /// <summary>
        /// The manufacturer's backend refused the news of a contract.
        /// </summary>
        public static WebhookEventType  ContractRejectedByOEM            { get; }
            = Register("mo.contract.rejected.by.oem");

        /// <summary>
        /// The manufacturer's backend did not answer properly, and the news is being retried.
        /// </summary>
        public static WebhookEventType  ContractQueuedToOEM              { get; }
            = Register("mo.contract.queued.to.oem");

        #endregion

        #region Contracts, as the vehicle manufacturer sees them

        /// <summary>
        /// A new contract is waiting in the pool for one of the manufacturer's vehicles.
        /// </summary>
        public static WebhookEventType  ContractCreated                  { get; }
            = Register("oem.contract.created");

        /// <summary>
        /// A contract of one of the manufacturer's vehicles was replaced.
        /// </summary>
        public static WebhookEventType  ContractUpdated                  { get; }
            = Register("oem.contract.updated");

        /// <summary>
        /// A contract of one of the manufacturer's vehicles is gone.
        /// </summary>
        public static WebhookEventType  ContractDeleted                  { get; }
            = Register("oem.contract.deleted");

        #endregion

        #endregion


        #region Operator overloading

        #region Operator == (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (WebhookEventType WebhookEventType1,
                                           WebhookEventType WebhookEventType2)

            => WebhookEventType1.Equals(WebhookEventType2);

        #endregion

        #region Operator != (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (WebhookEventType WebhookEventType1,
                                           WebhookEventType WebhookEventType2)

            => !WebhookEventType1.Equals(WebhookEventType2);

        #endregion

        #region Operator <  (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (WebhookEventType WebhookEventType1,
                                          WebhookEventType WebhookEventType2)

            => WebhookEventType1.CompareTo(WebhookEventType2) < 0;

        #endregion

        #region Operator <= (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (WebhookEventType WebhookEventType1,
                                           WebhookEventType WebhookEventType2)

            => WebhookEventType1.CompareTo(WebhookEventType2) <= 0;

        #endregion

        #region Operator >  (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (WebhookEventType WebhookEventType1,
                                          WebhookEventType WebhookEventType2)

            => WebhookEventType1.CompareTo(WebhookEventType2) > 0;

        #endregion

        #region Operator >= (WebhookEventType1, WebhookEventType2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookEventType1">An event type.</param>
        /// <param name="WebhookEventType2">Another event type.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (WebhookEventType WebhookEventType1,
                                           WebhookEventType WebhookEventType2)

            => WebhookEventType1.CompareTo(WebhookEventType2) >= 0;

        #endregion

        #endregion

        #region IComparable<WebhookEventType> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two event types.
        /// </summary>
        /// <param name="Object">An event type to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is WebhookEventType eventType
                   ? CompareTo(eventType)
                   : throw new ArgumentException("The given object is not a webhook event type!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(WebhookEventType)

        /// <summary>
        /// Compares two event types.
        /// </summary>
        /// <param name="WebhookEventType">An event type to compare with.</param>
        public Int32 CompareTo(WebhookEventType WebhookEventType)

            => String.Compare(InternalId,
                              WebhookEventType.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<WebhookEventType> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two event types for equality.
        /// </summary>
        /// <param name="Object">An event type to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is WebhookEventType eventType &&
                   Equals(eventType);

        #endregion

        #region Equals(WebhookEventType)

        /// <summary>
        /// Compares two event types for equality.
        /// </summary>
        /// <param name="WebhookEventType">An event type to compare with.</param>
        public Boolean Equals(WebhookEventType WebhookEventType)

            => String.Equals(InternalId,
                             WebhookEventType.InternalId,
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
