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
    /// Extension methods for webhook endpoint identifications.
    /// </summary>
    public static class WebhookIdExtensions
    {

        /// <summary>
        /// Indicates whether this webhook endpoint identification is null or empty.
        /// </summary>
        /// <param name="WebhookId">A webhook endpoint identification.</param>
        public static Boolean IsNullOrEmpty(this Webhook_Id? WebhookId)
            => !WebhookId.HasValue || WebhookId.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this webhook endpoint identification is NOT null or empty.
        /// </summary>
        /// <param name="WebhookId">A webhook endpoint identification.</param>
        public static Boolean IsNotNullOrEmpty(this Webhook_Id? WebhookId)
            => WebhookId.HasValue && WebhookId.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The identification a webhook service gives one registered endpoint.
    /// </summary>
    /// <remarks>
    /// The specification puts no format on it at all - "unique identifier for the object", and an
    /// example that is eight lowercase letters. So anything that can be a path segment is read,
    /// and what this library hands out looks like the example.
    /// </remarks>
    public readonly struct Webhook_Id : IId<Webhook_Id>
    {

        #region Data

        /// <summary>
        /// The internal identification.
        /// </summary>
        private readonly String InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this webhook endpoint identification is null or empty.
        /// </summary>
        public Boolean IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this webhook endpoint identification is NOT null or empty.
        /// </summary>
        public Boolean IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the webhook endpoint identification.
        /// </summary>
        public UInt64 Length
            => (UInt64) (InternalId?.Length ?? 0);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook endpoint identification based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a webhook endpoint identification.</param>
        private Webhook_Id(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (static) NewRandom(Length = 16)

        /// <summary>
        /// Create a new random webhook endpoint identification.
        /// </summary>
        /// <param name="Length">How many characters.</param>
        public static Webhook_Id NewRandom(Byte Length = 16)
        {

            const String alphanumerics = "abcdefghijklmnopqrstuvwxyz0123456789";

            return new (
                       new String(Enumerable.Range(0, Length).
                                             Select(_ => alphanumerics[Random.Shared.Next(alphanumerics.Length)]).
                                             ToArray())
                   );

        }

        #endregion

        #region (static) Parse    (Text)

        /// <summary>
        /// Parse the given text as a webhook endpoint identification.
        /// </summary>
        /// <param name="Text">A text representation of a webhook endpoint identification.</param>
        public static Webhook_Id Parse(String Text)
        {

            if (TryParse(Text, out var webhookId))
                return webhookId;

            throw new ArgumentException($"Invalid text representation of a webhook endpoint identification: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse (Text)

        /// <summary>
        /// Try to parse the given text as a webhook endpoint identification.
        /// </summary>
        /// <param name="Text">A text representation of a webhook endpoint identification.</param>
        public static Webhook_Id? TryParse(String Text)
        {

            if (TryParse(Text, out var webhookId))
                return webhookId;

            return null;

        }

        #endregion

        #region (static) TryParse (Text, out WebhookId)

        /// <summary>
        /// Try to parse the given text as a webhook endpoint identification.
        /// </summary>
        /// <param name="Text">A text representation of a webhook endpoint identification.</param>
        /// <param name="WebhookId">The parsed webhook endpoint identification.</param>
        public static Boolean TryParse(String Text, out Webhook_Id WebhookId)
        {

            var text = Text.Trim();

            // Anything that can be one path segment. A slash or whitespace in it would make the
            // identification unaddressable, which is the only actual constraint there is.
            if (text.IsNotNullOrEmpty() &&
                text.IndexOfAny([ '/', '\\', ' ', '\t', '?', '#' ]) < 0)
            {
                WebhookId = new Webhook_Id(text);
                return true;
            }

            WebhookId = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this webhook endpoint identification.
        /// </summary>
        public Webhook_Id Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Operator overloading

        #region Operator == (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (Webhook_Id WebhookId1,
                                           Webhook_Id WebhookId2)

            => WebhookId1.Equals(WebhookId2);

        #endregion

        #region Operator != (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (Webhook_Id WebhookId1,
                                           Webhook_Id WebhookId2)

            => !WebhookId1.Equals(WebhookId2);

        #endregion

        #region Operator <  (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (Webhook_Id WebhookId1,
                                          Webhook_Id WebhookId2)

            => WebhookId1.CompareTo(WebhookId2) < 0;

        #endregion

        #region Operator <= (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (Webhook_Id WebhookId1,
                                           Webhook_Id WebhookId2)

            => WebhookId1.CompareTo(WebhookId2) <= 0;

        #endregion

        #region Operator >  (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (Webhook_Id WebhookId1,
                                          Webhook_Id WebhookId2)

            => WebhookId1.CompareTo(WebhookId2) > 0;

        #endregion

        #region Operator >= (WebhookId1, WebhookId2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="WebhookId1">A webhook endpoint identification.</param>
        /// <param name="WebhookId2">Another webhook endpoint identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (Webhook_Id WebhookId1,
                                           Webhook_Id WebhookId2)

            => WebhookId1.CompareTo(WebhookId2) >= 0;

        #endregion

        #endregion

        #region IComparable<Webhook_Id> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two webhook endpoint identifications.
        /// </summary>
        /// <param name="Object">A webhook endpoint identification to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is Webhook_Id webhookId
                   ? CompareTo(webhookId)
                   : throw new ArgumentException("The given object is not a webhook endpoint identification!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(WebhookId)

        /// <summary>
        /// Compares two webhook endpoint identifications.
        /// </summary>
        /// <param name="WebhookId">A webhook endpoint identification to compare with.</param>
        public Int32 CompareTo(Webhook_Id WebhookId)

            => String.Compare(InternalId,
                              WebhookId.InternalId,
                              StringComparison.Ordinal);

        #endregion

        #endregion

        #region IEquatable<Webhook_Id> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two webhook endpoint identifications for equality.
        /// </summary>
        /// <param name="Object">A webhook endpoint identification to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is Webhook_Id webhookId &&
                   Equals(webhookId);

        #endregion

        #region Equals(WebhookId)

        /// <summary>
        /// Compares two webhook endpoint identifications for equality.
        /// </summary>
        /// <param name="WebhookId">A webhook endpoint identification to compare with.</param>
        public Boolean Equals(Webhook_Id WebhookId)

            => String.Equals(InternalId,
                             WebhookId.InternalId,
                             StringComparison.Ordinal);

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => InternalId?.GetHashCode() ?? 0;

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
