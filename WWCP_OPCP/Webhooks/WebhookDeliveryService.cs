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

using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// What became of one event on its way to one endpoint.
    /// </summary>
    /// <param name="Endpoint">Where it was sent.</param>
    /// <param name="Event">What was sent.</param>
    /// <param name="Delivered">Whether the partner acknowledged it.</param>
    /// <param name="HTTPStatusCode">What the partner answered last, when it answered.</param>
    /// <param name="Attempts">How many times it was tried.</param>
    /// <param name="Error">Why it did not arrive, when it did not.</param>
    public sealed record WebhookDelivery(WebhookEndpoint  Endpoint,
                                         WebhookEvent     Event,
                                         Boolean          Delivered,
                                         HTTPStatusCode?  HTTPStatusCode   = null,
                                         Int32            Attempts         = 1,
                                         String?          Error            = null);


    /// <summary>
    /// Tells partners what happened.
    ///
    /// An event reaches an endpoint if the partner asked for that kind of event, if the endpoint
    /// is enabled, and if the partner is allowed to hear about the vehicle or the contract it is
    /// about. Every delivery carries a signature made with that endpoint's own secret, which is
    /// the whole of what lets a partner tell an event from this ecosystem from one somebody else
    /// invented.
    /// </summary>
    public class WebhookDeliveryService
    {

        #region Data

        /// <summary>
        /// The header the narrative documentation's payload example uses, with the algorithm
        /// named in front of the signature.
        /// </summary>
        public const String SignatureHeader             = "X-Hubject-Signature";

        /// <summary>
        /// The header the payload document requires, whose example is the bare hexadecimal.
        /// </summary>
        public const String BareSignatureHeader         = "payload-signature";

        /// <summary>
        /// The header the same documentation's validation section - and both of its worked code
        /// examples - reads instead. Accepted on the way in; not written.
        /// </summary>
        public const String OperatorSignatureHeader     = "X-Operator-Signature";

        /// <summary>
        /// What the signature is prefixed with, to leave room for it ever having been made another
        /// way. The documentation calls this out as protection against a downgrade attack.
        /// </summary>
        public const String SignaturePrefix             = "sha256=";

        private Int32                    outstanding;
        private TaskCompletionSource     idle   = new (TaskCreationOptions.RunContinuationsAsynchronously);

        #endregion

        #region Properties

        /// <summary>
        /// Where the registered endpoints are.
        /// </summary>
        public IWebhookEndpointStore  Endpoints         { get; }

        /// <summary>
        /// How many times a delivery is tried in all.
        /// </summary>
        public Byte                   MaximumAttempts   { get; }

        /// <summary>
        /// How long to wait between tries.
        /// </summary>
        public TimeSpan               RetryInterval     { get; }

        /// <summary>
        /// How long to wait for a partner to answer.
        /// </summary>
        public TimeSpan               RequestTimeout    { get; }

        #endregion

        #region Events

        /// <summary>
        /// A delivery finished, one way or the other.
        /// </summary>
        public event Func<WebhookDelivery, Task>?  OnDelivery;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook delivery service.
        /// </summary>
        /// <param name="Endpoints">Where the registered endpoints are.</param>
        /// <param name="MaximumAttempts">How many times a delivery is tried in all.</param>
        /// <param name="RetryInterval">How long to wait between tries.</param>
        /// <param name="RequestTimeout">How long to wait for a partner to answer.</param>
        /// <remarks>
        /// The defaults are the specification's: a server error is retried three times at hourly
        /// intervals, after which the event is dropped.
        /// </remarks>
        public WebhookDeliveryService(IWebhookEndpointStore?  Endpoints         = null,
                                      Byte?                   MaximumAttempts   = null,
                                      TimeSpan?               RetryInterval     = null,
                                      TimeSpan?               RequestTimeout    = null)
        {

            this.Endpoints        = Endpoints ?? new InMemoryWebhookEndpointStore();
            this.MaximumAttempts  = MaximumAttempts ?? 4;
            this.RetryInterval    = RetryInterval   ?? TimeSpan.FromHours(1);
            this.RequestTimeout   = RequestTimeout  ?? TimeSpan.FromSeconds(30);

        }

        #endregion


        #region Publish  (Event, CancellationToken = default)

        /// <summary>
        /// Send an event to every endpoint that asked for it and is allowed to hear it.
        /// </summary>
        /// <param name="Event">What happened.</param>
        /// <param name="CancellationToken">An optional token to cancel the deliveries.</param>
        /// <returns>What became of each delivery.</returns>
        public Task<IEnumerable<WebhookDelivery>> Publish(WebhookEvent       Event,
                                                          CancellationToken  CancellationToken   = default)
        {

            Enter();

            return PublishCore(Event, CancellationToken);

        }

        #endregion

        #region (private) PublishCore(Event, CancellationToken)

        /// <summary>
        /// Send an event, and account for it having finished. The caller has already counted it
        /// as in flight.
        /// </summary>
        private async Task<IEnumerable<WebhookDelivery>> PublishCore(WebhookEvent       Event,
                                                                     CancellationToken  CancellationToken)
        {

            try
            {

                var body       = Encoding.UTF8.GetBytes(Event.ToJSON().ToString(Formatting.None));

                var recipients = (await Endpoints.GetAll()).Where(endpoint => MayReceive(endpoint, Event)).ToArray();

                var deliveries = await Task.WhenAll(
                                           recipients.Select(endpoint => Deliver(endpoint, Event, body, CancellationToken))
                                       );

                if (OnDelivery is not null)
                    foreach (var delivery in deliveries)
                        await OnDelivery.Invoke(delivery);

                return deliveries;

            }
            finally
            {
                Leave();
            }

        }

        #endregion

        #region PublishInBackground(Event)

        /// <summary>
        /// Send an event without waiting for it to arrive.
        /// </summary>
        /// <param name="Event">What happened.</param>
        /// <remarks>
        /// This is what the ecosystem's own operations use. A delivery that has to be retried
        /// takes as long as the retry interval - by default hours - and an HTTP request that
        /// deleted a certificate must not still be open when the last partner finally answers.
        /// A delivery that throws is swallowed here, because nothing upstream can act on it;
        /// <see cref="OnDelivery"/> is where a deployment watches what became of one.
        /// </remarks>
        public void PublishInBackground(WebhookEvent Event)
        {

            // Counted as in flight before the task is even started, so that anything which
            // returns after this call can rely on WhenIdle actually waiting for the delivery.
            // Counting it inside the task would leave a window in which nothing is in flight
            // yet and nothing has happened either.
            Enter();

            _ = Task.Run(async () => {
                    try
                    {
                        await PublishCore(Event, CancellationToken.None);
                    }
                    catch
                    { }
                });

        }

        #endregion

        #region WhenIdle (Timeout = null)

        /// <summary>
        /// Wait until nothing is in flight.
        /// </summary>
        /// <param name="Timeout">How long to wait at most.</param>
        /// <remarks>
        /// For anything that has to observe what a background delivery did - a test, or a
        /// deployment shutting down without dropping events on the floor.
        /// </remarks>
        public async Task WhenIdle(TimeSpan? Timeout = null)
        {

            var pending = Volatile.Read(ref idle).Task;

            if (Volatile.Read(ref outstanding) == 0)
                return;

            await Task.WhenAny(
                      pending,
                      Task.Delay(Timeout ?? TimeSpan.FromSeconds(30))
                  );

        }

        #endregion


        #region (static) Sign            (Body, Secret)

        /// <summary>
        /// The signature of one delivery: an HMAC-SHA256 over the body exactly as it goes on the
        /// wire, as lowercase hexadecimal.
        /// </summary>
        /// <param name="Body">The request body, byte for byte.</param>
        /// <param name="Secret">The endpoint's signing secret.</param>
        /// <remarks>
        /// Over the raw bytes and not over a re-serialization of them: a partner computes this
        /// over what it received, and any two JSON writers that disagree about spacing would
        /// otherwise disagree about the signature.
        /// </remarks>
        public static String Sign(Byte[]  Body,
                                  String  Secret)

            => Convert.ToHexString(
                   HMACSHA256.HashData(
                       Encoding.UTF8.GetBytes(Secret),
                       Body
                   )
               ).ToLowerInvariant();

        #endregion

        #region (static) VerifySignature (Body, Secret, Signature)

        /// <summary>
        /// Check that a delivery really was made by whoever holds the endpoint's secret.
        /// </summary>
        /// <param name="Body">The request body, byte for byte.</param>
        /// <param name="Secret">The endpoint's signing secret.</param>
        /// <param name="Signature">The signature header, with or without its algorithm prefix.</param>
        /// <remarks>
        /// The comparison is constant-time, as the documentation asks: a plain string comparison
        /// returns after the first differing character, which tells an attacker how much of a
        /// guess was right.
        /// </remarks>
        public static Boolean VerifySignature(Byte[]   Body,
                                              String   Secret,
                                              String?  Signature)
        {

            if (Signature.IsNullOrEmpty() || Secret.IsNullOrEmpty())
                return false;

            var offered = Signature!.Trim();

            if (offered.StartsWith(SignaturePrefix, StringComparison.OrdinalIgnoreCase))
                offered = offered[SignaturePrefix.Length..];

            return CryptographicOperations.FixedTimeEquals(
                       Encoding.ASCII.GetBytes(offered.ToLowerInvariant()),
                       Encoding.ASCII.GetBytes(Sign(Body, Secret))
                   );

        }

        #endregion

        #region (static) SignatureOf     (Request)

        /// <summary>
        /// Read the signature out of a request, under whichever of the three names it arrived.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        /// <remarks>
        /// The specification uses all three: the payload document requires
        /// <c>payload-signature</c> and describes <c>X-Hubject-Signature</c> beside it, and the
        /// narrative documentation's validation section - along with both of its worked code
        /// examples - reads <c>X-Operator-Signature</c>.
        /// </remarks>
        public static String? SignatureOf(HTTPRequest Request)

            => new[] { SignatureHeader, BareSignatureHeader, OperatorSignatureHeader }.
                   Select(Request.GetHeaderField).
                   FirstOrDefault(value => value.IsNotNullOrEmpty());

        #endregion


        #region (private, static) MayReceive(Endpoint, Event)

        /// <summary>
        /// Whether this endpoint gets this event: it asked for the kind, and it is allowed to
        /// hear about the thing.
        /// </summary>
        private static Boolean MayReceive(WebhookEndpoint  Endpoint,
                                          WebhookEvent     Event)
        {

            if (!Endpoint.Wants(Event.EventType))
                return false;

            var emaId = Event.EMAId;

            if (emaId.HasValue && !Endpoint.MayHearAbout(emaId.Value))
                return false;

            var pcid = Event.PCID;

            if (pcid.HasValue && !Endpoint.MayHearAbout(pcid.Value))
                return false;

            return true;

        }

        #endregion

        #region (private) Deliver(Endpoint, Event, Body, CancellationToken)

        /// <summary>
        /// Send one event to one endpoint, retrying while the partner's own side is failing.
        /// </summary>
        /// <remarks>
        /// A server error means the partner meant to take this and could not, so it is tried
        /// again. A client error means the partner looked at it and said no, and repeating it
        /// would only say the same thing more often.
        /// </remarks>
        private async Task<WebhookDelivery> Deliver(WebhookEndpoint    Endpoint,
                                                    WebhookEvent       Event,
                                                    Byte[]             Body,
                                                    CancellationToken  CancellationToken)
        {

            var signature       = Endpoint.Secret.IsNotNullOrEmpty()
                                      ? Sign(Body, Endpoint.Secret!)
                                      : null;

            HTTPStatusCode?  lastStatusCode  = null;
            String?          lastError       = null;

            for (var attempt = 1; attempt <= MaximumAttempts; attempt++)
            {

                if (attempt > 1)
                {
                    try
                    {
                        await Task.Delay(RetryInterval, CancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        return new WebhookDelivery(Endpoint, Event, false, lastStatusCode, attempt - 1, "The delivery was cancelled.");
                    }
                }

                try
                {

                    using var client = new HTTPClient(Endpoint.URL);

                    var response = await client.RunRequest(
                                             HTTPMethod.POST,
                                             Endpoint.URL.Path,
                                             ContentType:  HTTPContentType.Application.JSON_UTF8,
                                             Content:      Body,
                                             RequestBuilder: builder => {

                                                 if (signature is not null)
                                                 {
                                                     builder.SetHeaderField(SignatureHeader,      SignaturePrefix + signature);
                                                     builder.SetHeaderField(BareSignatureHeader,  signature);
                                                 }

                                             },
                                             RequestTimeout:     RequestTimeout,
                                             CancellationToken:  CancellationToken
                                         ).ConfigureAwait(false);

                    lastStatusCode = response.HTTPStatusCode;

                    if (response.HTTPStatusCode.Code >= 200 &&
                        response.HTTPStatusCode.Code <  300)
                    {
                        return new WebhookDelivery(Endpoint, Event, true, response.HTTPStatusCode, attempt);
                    }

                    lastError = $"HTTP {response.HTTPStatusCode.Code} {response.HTTPStatusCode.Name}";

                    // The partner read it and refused it. Saying it again would not help.
                    if (response.HTTPStatusCode.Code < 500)
                        return new WebhookDelivery(Endpoint, Event, false, response.HTTPStatusCode, attempt, lastError);

                }
                catch (Exception e)
                {
                    // Nothing answered at all, which is the partner's side failing just as much
                    // as a 500 is.
                    lastStatusCode  = null;
                    lastError       = e.Message;
                }

            }

            return new WebhookDelivery(Endpoint, Event, false, lastStatusCode, MaximumAttempts, lastError);

        }

        #endregion

        #region (private) Enter() / Leave()

        private void Enter()
        {
            if (Interlocked.Increment(ref outstanding) == 1)
                Interlocked.Exchange(ref idle, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        }

        private void Leave()
        {
            if (Interlocked.Decrement(ref outstanding) == 0)
                Volatile.Read(ref idle).TrySetResult();
        }

        #endregion

    }

}
