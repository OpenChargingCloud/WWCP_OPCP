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

using System.Text;

using Newtonsoft.Json;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// The webhook service: how a partner finds out that something happened to its assets without
    /// asking the ecosystem over and over whether anything has.
    /// </summary>
    [TestFixture]
    public class WebhookTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly PCID    pcid       = PCID.  Parse("ECD12345671234567");
        private static readonly PCID    otherCar   = PCID.  Parse("XYZ98765439876543");
        private static readonly EMA_Id  emaId      = EMA_Id.Parse("DEECD123456789");
        private static readonly EMA_Id  otherEMAId = EMA_Id.Parse("DEXYZ987654321");

        private WebhookReceiver_HTTPAPI  receiverOne  = null!;
        private WebhookReceiver_HTTPAPI  receiverTwo  = null!;

        private readonly List<WebhookEvent>  arrivedAtOne  = [];
        private readonly List<WebhookEvent>  arrivedAtTwo  = [];
        private readonly List<String>        refusedAtOne  = [];

        /// <summary>
        /// Two partner backends, mounted once: an HTTP API belongs to one path for the life of
        /// the server it sits on.
        /// </summary>
        [OneTimeSetUp]
        public void MountReceivers()
        {

            receiverOne = new WebhookReceiver_HTTPAPI(httpServer, RootPath: HTTPPath.Parse("/payload/one/"));
            receiverTwo = new WebhookReceiver_HTTPAPI(httpServer, RootPath: HTTPPath.Parse("/payload/two/"));

            receiverOne.OnEvent   += webhookEvent => { lock (arrivedAtOne) arrivedAtOne.Add(webhookEvent); return Task.CompletedTask; };
            receiverTwo.OnEvent   += webhookEvent => { lock (arrivedAtTwo) arrivedAtTwo.Add(webhookEvent); return Task.CompletedTask; };
            receiverOne.OnRefused += reason       => { lock (refusedAtOne) refusedAtOne.Add(reason);       return Task.CompletedTask; };

        }

        [SetUp]
        public void ForgetWhatArrived()
        {

            arrivedAtOne.Clear();
            arrivedAtTwo.Clear();
            refusedAtOne.Clear();

            receiverOne.AnswerWith = HTTPStatusCode.OK;
            receiverTwo.AnswerWith = HTTPStatusCode.OK;
            receiverOne.Secret     = null;
            receiverTwo.Secret     = null;

        }


        private URL One
            => URL.Parse($"{baseURL}/payload/one/");

        private URL Two
            => URL.Parse($"{baseURL}/payload/two/");

        /// <summary>
        /// A client acting as one named partner - the name is what the service records an
        /// endpoint's owner as.
        /// </summary>
        private Webhook_HTTPClient Partner(String          Name,
                                           OPCPRole[]      Roles,
                                           WMI[]?          WMIs          = null,
                                           Provider_Id[]?  ProviderIds   = null)

            => new (baseURL,
                    new StaticAccessTokenProvider(
                        tokenIssuer.IssueToken(Roles, WMIs, ProviderIds, ClientName: Name).AccessToken
                    ));

        /// <summary>
        /// Register an endpoint and tell the receiver behind it what it was given to check
        /// signatures with.
        /// </summary>
        private async Task<WebhookEndpoint> Subscribe(Webhook_HTTPClient       Client,
                                                      URL                      URL,
                                                      WebhookReceiver_HTTPAPI  Receiver,
                                                      params WebhookEventType[]  Events)
        {

            var created = await Client.CreateEndpoint(URL, Events);

            Assert.That(created.IsSuccess,  Is.True, created.Error?.ToString());

            Receiver.Secret = created.Data!.Secret;

            return created.Data;

        }

        #endregion


        #region A_partner_registers_an_endpoint_and_is_given_a_secret_for_it()

        /// <summary>
        /// The secret is the one thing a partner cannot choose and cannot compute: without it,
        /// nothing tells an event from this ecosystem apart from one somebody else invented.
        /// </summary>
        [Test]
        public async Task A_partner_registers_an_endpoint_and_is_given_a_secret_for_it()
        {

            var created = await Partner("oem-backend", [ OPCPRole.OEM ]).CreateEndpoint(
                                    One,
                                    [ WebhookEventType.ContractCreated, WebhookEventType.ContractDeleted ],
                                    "Contracts of our cars"
                                );

            Assert.That(created.IsSuccess,  Is.True, created.Error?.ToString());

            Assert.Multiple(() => {

                Assert.That(created.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.Created));
                Assert.That(created.Data!.Id.IsNotNullOrEmpty,  Is.True);
                Assert.That(created.Data.Secret,           Is.Not.Null.And.Length.AtLeast(32));
                Assert.That(created.Data.URL,              Is.EqualTo(One));
                Assert.That(created.Data.EnabledEvents,    Is.EquivalentTo(new[] { WebhookEventType.ContractCreated,
                                                                                   WebhookEventType.ContractDeleted }));
                Assert.That(created.Data.UserName,         Is.EqualTo("oem-backend@clients"));
                Assert.That(created.Data.IsEnabled,        Is.True);

            });

        }

        #endregion

        #region An_endpoint_can_be_read_changed_and_given_up()

        [Test]
        public async Task An_endpoint_can_be_read_changed_and_given_up()
        {

            var partner  = Partner("oem-backend", [ OPCPRole.OEM ]);

            var created  = await Subscribe(partner, One, receiverOne, WebhookEventType.ContractCreated);

            var read     = await partner.GetEndpoint(created.Id);

            var changed  = await partner.UpdateEndpoint(
                                     created.Id,
                                     new WebhookEndpoint(
                                         Two,
                                         [ WebhookEventType.ContractCreated, WebhookEventType.ContractDeleted ],
                                         Status: WebhookEndpoint.StatusDisabled
                                     ));

            var listed   = await partner.GetEndpoints();

            var deleted  = await partner.DeleteEndpoint(created.Id);

            var gone     = await partner.GetEndpoint(created.Id);

            Assert.Multiple(() => {

                Assert.That(read.Data!.Id,             Is.EqualTo(created.Id));
                Assert.That(read.Data.Secret,          Is.EqualTo(created.Secret));

                Assert.That(changed.IsSuccess,         Is.True, changed.Error?.ToString());
                Assert.That(changed.Data!.URL,         Is.EqualTo(Two));
                Assert.That(changed.Data.IsEnabled,    Is.False);

                // An update edits the subscription, not the subscriber.
                Assert.That(changed.Data.Secret,       Is.EqualTo(created.Secret));
                Assert.That(changed.Data.Id,           Is.EqualTo(created.Id));

                Assert.That(listed.Data,               Has.Exactly(1).Items);

                Assert.That(deleted.IsSuccess,         Is.True);
                Assert.That(gone.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.NotFound));

            });

        }

        #endregion

        #region A_partner_sees_only_its_own_endpoints()

        /// <summary>
        /// An endpoint is a URL and a secret. Somebody else's is answered as not found rather
        /// than as forbidden - which identifications exist is not something to be learned by
        /// asking for them one at a time.
        /// </summary>
        [Test]
        public async Task A_partner_sees_only_its_own_endpoints()
        {

            var first   = Partner("first-partner",  [ OPCPRole.OEM ]);
            var second  = Partner("second-partner", [ OPCPRole.MO  ]);

            var mine    = await Subscribe(first, One, receiverOne, WebhookEventType.ContractCreated);
            await         Subscribe(second, Two, receiverTwo, WebhookEventType.ContractDeleted);

            var ours    = await first. GetEndpoints();
            var theirs  = await second.GetEndpoints();
            var peek    = await second.GetEndpoint(mine.Id);

            Assert.Multiple(() => {
                Assert.That(ours.  Data,             Has.Exactly(1).Items);
                Assert.That(theirs.Data,             Has.Exactly(1).Items);
                Assert.That(ours.  Data!.First().Id, Is.EqualTo(mine.Id));
                Assert.That(peek.HTTPStatusCode,     Is.EqualTo(HTTPStatusCode.NotFound));
            });

        }

        #endregion


        #region An_event_arrives_signed_with_the_endpoints_own_secret()

        /// <summary>
        /// The whole point of the service, and the check a partner has to make before believing
        /// anything it receives.
        /// </summary>
        [Test]
        public async Task An_event_arrives_signed_with_the_endpoints_own_secret()
        {

            await Subscribe(Partner("oem-backend", [ OPCPRole.OEM ]), One, receiverOne,
                            WebhookEventType.ContractCreated);

            var deliveries = await webhookAPI.Delivery.Publish(
                                       WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid)
                                   );

            Assert.Multiple(() => {

                Assert.That(deliveries,                    Has.Exactly(1).Items);
                Assert.That(deliveries.First().Delivered,  Is.True);
                Assert.That(deliveries.First().Attempts,   Is.EqualTo(1));

                Assert.That(arrivedAtOne,                  Has.Exactly(1).Items);
                Assert.That(arrivedAtOne[0].EventType,     Is.EqualTo(WebhookEventType.ContractCreated));
                Assert.That(arrivedAtOne[0].EMAId,         Is.EqualTo(emaId));
                Assert.That(arrivedAtOne[0].PCID,          Is.EqualTo(pcid));

                Assert.That(refusedAtOne,                  Is.Empty);

            });

        }

        #endregion

        #region A_delivery_nobody_could_have_signed_is_refused()

        /// <summary>
        /// The receiver checks the signature before it looks at the body at all: a delivery that
        /// cannot prove where it came from is not a malformed event, it is somebody else's.
        /// </summary>
        [Test]
        public async Task A_delivery_nobody_could_have_signed_is_refused()
        {

            await Subscribe(Partner("oem-backend", [ OPCPRole.OEM ]), One, receiverOne,
                            WebhookEventType.ContractCreated);

            // The partner thinks the secret is something else - which is what an attacker sending
            // events to this endpoint would be up against.
            receiverOne.Secret = WebhookEndpoint.NewSecret();

            var deliveries = await webhookAPI.Delivery.Publish(
                                       WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid)
                                   );

            Assert.Multiple(() => {

                Assert.That(arrivedAtOne,                       Is.Empty);
                Assert.That(refusedAtOne,                       Has.Exactly(1).Items);

                Assert.That(deliveries.First().Delivered,       Is.False);
                Assert.That(deliveries.First().HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));

                // Refused, not failed: the partner looked at it and said no, and saying it again
                // would only say the same thing more often.
                Assert.That(deliveries.First().Attempts,        Is.EqualTo(1));

            });

        }

        #endregion

        #region The_signature_is_over_the_bytes_that_were_actually_sent()

        /// <summary>
        /// Over the raw body rather than over a re-serialization of it: a partner computes this
        /// over what arrived, and any two JSON writers that disagree about spacing would otherwise
        /// disagree about the signature.
        /// </summary>
        [Test]
        public void The_signature_is_over_the_bytes_that_were_actually_sent()
        {

            var secret  = WebhookEndpoint.NewSecret();

            var body    = Encoding.UTF8.GetBytes(
                              WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid).
                                  ToJSON().ToString(Formatting.None)
                          );

            var tampered = body.ToArray();
            tampered[^2] = (Byte) (tampered[^2] ^ 0x01);

            var signature = WebhookDeliveryService.Sign(body, secret);

            Assert.Multiple(() => {

                // With and without the algorithm prefix, because the specification's own two
                // headers carry it differently.
                Assert.That(WebhookDeliveryService.VerifySignature(body, secret, signature),              Is.True);
                Assert.That(WebhookDeliveryService.VerifySignature(body, secret, "sha256=" + signature),  Is.True);

                Assert.That(WebhookDeliveryService.VerifySignature(tampered, secret, signature),          Is.False);
                Assert.That(WebhookDeliveryService.VerifySignature(body, WebhookEndpoint.NewSecret(), signature),  Is.False);
                Assert.That(WebhookDeliveryService.VerifySignature(body, secret, null),                   Is.False);
                Assert.That(WebhookDeliveryService.VerifySignature(body, secret, ""),                     Is.False);

                Assert.That(signature,  Has.Length.EqualTo(64), "A SHA-256 HMAC as lowercase hexadecimal.");

            });

        }

        #endregion


        #region Only_the_events_a_partner_asked_for_arrive()

        [Test]
        public async Task Only_the_events_a_partner_asked_for_arrive()
        {

            await Subscribe(Partner("oem-backend", [ OPCPRole.OEM ]), One, receiverOne,
                            WebhookEventType.ContractCreated);

            await webhookAPI.Delivery.Publish(WebhookEvent.ForContract(WebhookEventType.ContractDeleted, emaId, pcid));
            await webhookAPI.Delivery.Publish(WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid));

            Assert.Multiple(() => {
                Assert.That(arrivedAtOne,               Has.Exactly(1).Items);
                Assert.That(arrivedAtOne[0].EventType,  Is.EqualTo(WebhookEventType.ContractCreated));
            });

        }

        #endregion

        #region A_disabled_endpoint_is_told_nothing()

        [Test]
        public async Task A_disabled_endpoint_is_told_nothing()
        {

            var partner  = Partner("oem-backend", [ OPCPRole.OEM ]);
            var endpoint = await Subscribe(partner, One, receiverOne, WebhookEventType.ContractCreated);

            await partner.UpdateEndpoint(
                      endpoint.Id,
                      new WebhookEndpoint(One,
                                          [ WebhookEventType.ContractCreated ],
                                          Status: WebhookEndpoint.StatusDisabled)
                  );

            var deliveries = await webhookAPI.Delivery.Publish(
                                       WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid)
                                   );

            Assert.Multiple(() => {
                Assert.That(deliveries,    Is.Empty);
                Assert.That(arrivedAtOne,  Is.Empty);
            });

        }

        #endregion

        #region A_partner_only_hears_about_what_it_is_allowed_to_hear_about()

        /// <summary>
        /// The scoping fields are not decoration: without them a subscription would be a way of
        /// watching somebody else's cars. What an endpoint may hear comes from the token that
        /// registered it, not from the registration.
        /// </summary>
        [Test]
        public async Task A_partner_only_hears_about_what_it_is_allowed_to_hear_about()
        {

            var manufacturer = Partner("oem-backend", [ OPCPRole.OEM ], [ WMI.Parse("ECD") ]);
            var operatorOne  = Partner("mo-backend",  [ OPCPRole.MO  ], null, [ emaId.ProviderId ]);

            await Subscribe(manufacturer, One, receiverOne, WebhookEventType.ContractCreated);
            await Subscribe(operatorOne,  Two, receiverTwo, WebhookEventType.ContractCreated);

            // A car of this manufacturer, under a contract of this operator: both hear it.
            await webhookAPI.Delivery.Publish(WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid));

            // Somebody else's car and somebody else's contract: neither does.
            await webhookAPI.Delivery.Publish(WebhookEvent.ForContract(WebhookEventType.ContractCreated, otherEMAId, otherCar));

            Assert.Multiple(() => {

                Assert.That(arrivedAtOne,          Has.Exactly(1).Items);
                Assert.That(arrivedAtTwo,          Has.Exactly(1).Items);

                Assert.That(arrivedAtOne[0].PCID,  Is.EqualTo(pcid));
                Assert.That(arrivedAtTwo[0].EMAId, Is.EqualTo(emaId));

            });

        }

        #endregion

        #region A_partner_whose_backend_is_failing_is_tried_again()

        /// <summary>
        /// A server error means the partner meant to take this and could not. A client error
        /// means it looked at it and said no.
        /// </summary>
        [Test]
        public async Task A_partner_whose_backend_is_failing_is_tried_again()
        {

            await Subscribe(Partner("oem-backend", [ OPCPRole.OEM ]), One, receiverOne,
                            WebhookEventType.ContractCreated);

            receiverOne.AnswerWith = HTTPStatusCode.InternalServerError;

            var failing  = await webhookAPI.Delivery.Publish(
                                     WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid)
                                 );

            receiverOne.AnswerWith = HTTPStatusCode.BadRequest;

            var refusing = await webhookAPI.Delivery.Publish(
                                     WebhookEvent.ForContract(WebhookEventType.ContractCreated, emaId, pcid)
                                 );

            Assert.Multiple(() => {

                Assert.That(failing. First().Delivered,  Is.False);
                Assert.That(failing. First().Attempts,   Is.EqualTo(webhookAPI.Delivery.MaximumAttempts));

                Assert.That(refusing.First().Delivered,  Is.False);
                Assert.That(refusing.First().Attempts,   Is.EqualTo(1));

            });

        }

        #endregion


        #region A_root_admitted_to_the_pool_is_news()

        /// <summary>
        /// The first of the cascades: a charge point operator has to learn that a new anchor
        /// exists before certificates under it start arriving at its stations.
        /// </summary>
        [Test]
        public async Task A_root_admitted_to_the_pool_is_news()
        {

            await Subscribe(Partner("cpo-backend", [ OPCPRole.CPO ]), One, receiverOne,
                            WebhookEventType.RootCertificateAdded);

            var added = await NewRCPClient(OPCPRole.Admin).SaveRootCA(
                                  NewRootCA("V2G Root CA for the webhook test"),
                                  RootCertificateType.V2G
                              );

            Assert.That(added.IsSuccess,  Is.True, added.Error?.ToString());

            await webhookAPI.Delivery.WhenIdle(TimeSpan.FromSeconds(10));

            Assert.That(arrivedAtOne,  Has.Exactly(1).Items);

            Assert.Multiple(() => {
                Assert.That(arrivedAtOne[0].EventType,                             Is.EqualTo(WebhookEventType.RootCertificateAdded));
                Assert.That(arrivedAtOne[0].Payload.Value<String>("commonName"),   Is.EqualTo("V2G Root CA for the webhook test"));
                Assert.That(arrivedAtOne[0].Payload.Value<String>("rootType"),     Is.EqualTo("V2G"));
                Assert.That(arrivedAtOne[0].Payload.Value<String>("fingerprintSHA256"),  Is.Not.Null);
            });

        }

        #endregion

        #region A_vehicle_losing_its_certificate_is_news()

        /// <summary>
        /// And it is news the mobility operator needs, because every contract of that car went
        /// with it.
        /// </summary>
        [Test]
        public async Task A_vehicle_losing_its_certificate_is_news()
        {

            await SeedRootCertificates();

            await Subscribe(Partner("mo-backend", [ OPCPRole.MO ]), One, receiverOne,
                            WebhookEventType.ProvisioningCertificateDeleted);

            var vehicle      = pki.IssueProvisioningCertificate(pcid);
            var manufacturer = NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]);

            await manufacturer.AddOEMProvCert(
                      new ProvisioningCertificate(vehicle.Certificate,
                                                  pki.OEMSubCA1.Certificate,
                                                  pki.OEMSubCA2.Certificate));

            await manufacturer.DeleteOEMProvCert(pcid);

            await webhookAPI.Delivery.WhenIdle(TimeSpan.FromSeconds(10));

            Assert.That(arrivedAtOne,  Has.Exactly(1).Items);

            Assert.Multiple(() => {
                Assert.That(arrivedAtOne[0].EventType,  Is.EqualTo(WebhookEventType.ProvisioningCertificateDeleted));
                Assert.That(arrivedAtOne[0].PCID,       Is.EqualTo(pcid));
            });

        }

        #endregion

        #region A_contract_appearing_and_then_reaching_a_car_is_news_twice()

        /// <summary>
        /// The whole lifecycle as a partner sees it: a contract is filed, and later a car
        /// actually collects it. The second event is the one that says the contract is in use
        /// rather than merely on file.
        /// </summary>
        [Test]
        public async Task A_contract_appearing_and_then_reaching_a_car_is_news_twice()
        {

            await Subscribe(Partner("oem-backend", [ OPCPRole.OEM ]), One, receiverOne,
                            WebhookEventType.ContractCreated,
                            WebhookEventType.ContractDeliveredToOEM);

            var vehicle = pki.IssueProvisioningCertificate(pcid);

            await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.CPS)).AddSignedContractData(
                      NewContract(emaId, vehicle)
                  );

            await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.CPO)).GetSignedContractData(
                      TestContractDataCodec.EncodeInstallationRequest(pcid)
                  );

            await webhookAPI.Delivery.WhenIdle(TimeSpan.FromSeconds(10));

            Assert.That(arrivedAtOne,  Has.Exactly(2).Items);

            // Two independent deliveries: which one is written down first is not something to
            // assert, only that both arrived and each says what it should.
            var created   = arrivedAtOne.First(e => e.EventType == WebhookEventType.ContractCreated);
            var delivered = arrivedAtOne.First(e => e.EventType == WebhookEventType.ContractDeliveredToOEM);

            Assert.Multiple(() => {

                Assert.That(created.  EMAId,  Is.EqualTo(emaId));
                Assert.That(delivered.PCID,   Is.EqualTo(pcid));

                // A manufacturer's backend gets the contract certificate itself, which is what it
                // needs in order to know what its car is about to charge under.
                Assert.That(created.Payload.Value<String>("contractCert"),  Is.Not.Null);

            });

        }

        #endregion


        #region A_subscription_written_either_way_is_read()

        /// <summary>
        /// The management interface calls the field 'enabledEvents' and its own responses have
        /// been seen to call it 'events'. Both are read; the first is written.
        /// </summary>
        [Test]
        public async Task A_subscription_written_either_way_is_read()
        {

            var response = await new RawOPCPClient(
                                         baseURL,
                                         new StaticAccessTokenProvider(
                                             tokenIssuer.IssueToken([ OPCPRole.OEM ], ClientName: "legacy-partner").AccessToken
                                         )
                                     ).SendRaw(
                                         HTTPMethod.POST,
                                         $"{Webhook_HTTPClient.URLPrefix}/endpoints",
                                         new Newtonsoft.Json.Linq.JObject(
                                             new Newtonsoft.Json.Linq.JProperty("url",     One.ToString()),
                                             new Newtonsoft.Json.Linq.JProperty("events",  new Newtonsoft.Json.Linq.JArray("oem.contract.created"))
                                         )
                                     );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Created));

            var body = Newtonsoft.Json.Linq.JObject.Parse(Encoding.UTF8.GetString(response.HTTPBody ?? []));

            Assert.Multiple(() => {
                Assert.That(body["enabledEvents"],  Is.Not.Null, "It is written under the current name.");
                Assert.That(body["events"],         Is.Null);
            });

        }

        #endregion

        #region The_catalogue_covers_what_all_three_documents_name()

        /// <summary>
        /// The specification names these in three places and never the same list twice. All
        /// sixteen are here, because a partner subscribing to an event one document knows about
        /// should not be turned away by a service that read a different one.
        /// </summary>
        [Test]
        public void The_catalogue_covers_what_all_three_documents_name()
        {

            var catalogue = new[] {
                                WebhookEventType.RootCertificateAdded,
                                WebhookEventType.RootCertificateExpired,
                                WebhookEventType.RootCertificateRevoked,
                                WebhookEventType.ProvisioningCertificateDeleted,
                                WebhookEventType.ProvisioningCertificateUpdated,
                                WebhookEventType.FactoryReset,
                                WebhookEventType.FactoryResetDeprecated,
                                WebhookEventType.ContractCreatedSentToOEM,
                                WebhookEventType.ContractUpdatedSentToOEM,
                                WebhookEventType.ContractDeletedSentToOEM,
                                WebhookEventType.ContractDeliveredToOEM,
                                WebhookEventType.ContractRejectedByOEM,
                                WebhookEventType.ContractQueuedToOEM,
                                WebhookEventType.ContractCreated,
                                WebhookEventType.ContractUpdated,
                                WebhookEventType.ContractDeleted
                            };

            Assert.Multiple(() => {

                Assert.That(catalogue.Distinct().Count(),  Is.EqualTo(16));

                // The two the management interface's own enum leaves out.
                Assert.That(WebhookEventType.Parse("root.cert.revoked"),          Is.EqualTo(WebhookEventType.RootCertificateRevoked));
                Assert.That(WebhookEventType.Parse("mo.prov.cert.factory.reset"), Is.EqualTo(WebhookEventType.FactoryReset));

                // Which payload shape an event carries follows from its name.
                Assert.That(catalogue.Where(eventType => eventType.IsRootCertificateEvent).Count(),  Is.EqualTo(3));

            });

        }

        #endregion

        #region Registering_an_endpoint_needs_a_token()

        /// <summary>
        /// The interface document declares no security for any of these five operations. An
        /// endpoint registration decides who is told about somebody's cars, so it is
        /// authenticated like everything else here.
        /// </summary>
        [Test]
        public async Task Registering_an_endpoint_needs_a_token()
        {

            var response = await new Webhook_HTTPClient(baseURL).CreateEndpoint(
                                     One,
                                     [ WebhookEventType.ContractCreated ]
                                 );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));

        }

        #endregion

        #region An_endpoint_that_asks_for_no_events_is_refused()

        [Test]
        public async Task An_endpoint_that_asks_for_no_events_is_refused()
        {

            var response = await Partner("oem-backend", [ OPCPRole.OEM ]).CreateEndpoint(One, []);

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));

        }

        #endregion

    }

}
