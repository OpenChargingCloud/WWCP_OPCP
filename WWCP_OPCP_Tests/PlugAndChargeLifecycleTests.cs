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

using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Crypto;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests
{

    /// <summary>
    /// The whole Plug&amp;Charge story, once, through every service at once.
    ///
    /// Everything else in this suite tests one component against its own specification. This
    /// tests that the six of them are the same ecosystem: a certificate issued by one is accepted
    /// by the next, a contract signed by a third is found by a fourth, and the car at the end of
    /// it can open what it was given.
    /// </summary>
    [TestFixture]
    public class PlugAndChargeLifecycleTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly WMI          wmi     = WMI.   Parse("ECD");
        private static readonly PCID         pcid    = PCID.  Parse("ECD12345671234567");
        private static readonly EMA_Id       emaId   = EMA_Id.Parse("DEECD123456789");
        private static readonly EMA_Id       emaId2  = EMA_Id.Parse("DEECD987654321");

        private WebhookReceiver_HTTPAPI      partner  = null!;
        private readonly List<WebhookEvent>  heard    = [];

        [OneTimeSetUp]
        public void MountPartnerBackend()
        {

            partner = new WebhookReceiver_HTTPAPI(httpServer, RootPath: HTTPPath.Parse("/lifecycle/"));

            partner.OnEvent += webhookEvent => {
                                   lock (heard)
                                       heard.Add(webhookEvent);
                                   return Task.CompletedTask;
                               };

        }

        [SetUp]
        public void ForgetWhatWasHeard()
        {
            heard.Clear();
            partner.Secret = null;
        }


        private Int32 Heard(WebhookEventType EventType)
        {
            lock (heard)
                return heard.Count(webhookEvent => webhookEvent.EventType == EventType);
        }

        #endregion


        #region A_car_is_built_sold_charged_and_finally_forgotten()

        /// <summary>
        /// One car, from the factory to the scrapyard, through all six services.
        /// </summary>
        [Test]
        public async Task A_car_is_built_sold_charged_and_finally_forgotten()
        {

            #region ① A partner backend asks to be kept informed

            var subscription = await new Webhook_HTTPClient(
                                         baseURL,
                                         new StaticAccessTokenProvider(
                                             tokenIssuer.IssueToken([ OPCPRole.OEM ], [ wmi ], ClientName: "lifecycle-oem").AccessToken
                                         )
                                     ).CreateEndpoint(
                                         URL.Parse($"{baseURL}/lifecycle/"),
                                         [ WebhookEventType.RootCertificateAdded,
                                           WebhookEventType.ContractCreated,
                                           WebhookEventType.ContractDeliveredToOEM,
                                           WebhookEventType.ContractDeleted,
                                           WebhookEventType.ProvisioningCertificateDeleted ]
                                     );

            Assert.That(subscription.IsSuccess,  Is.True, subscription.Error?.ToString());

            partner.Secret = subscription.Data!.Secret;

            #endregion

            #region ② The ecosystem operator admits the three trust anchors

            var admin = NewRCPClient(OPCPRole.Admin);

            foreach (var (rootType, certificate) in new[] {
                         (RootCertificateType.V2G, pki.V2GRoot.Certificate),
                         (RootCertificateType.OEM, pki.OEMRoot.Certificate),
                         (RootCertificateType.MO,  pki.MORoot. Certificate)
                     })
            {
                var admitted = await admin.SaveRootCA(certificate, rootType);
                Assert.That(admitted.IsSuccess,  Is.True, $"The {rootType} root: {admitted.Error}");
            }

            #endregion

            #region ③ The manufacturer has the car's certificate issued by the V2G PKI

            var vehicleKeyPair = PKIFactory.GenerateECCKeyPair("secp256r1");

            var enrolled       = await new EST_HTTPClient(baseURL, TokenFor([ OPCPRole.OEM ], [ wmi ])).SimpleEnroll(
                                           CA_Id.Parse(CA_Type.OEM),
                                           CSRBuilder.Create(pcid.ToString(), vehicleKeyPair, "GraphDefined GmbH", "DE")
                                       );

            Assert.That(enrolled.IsSuccess,  Is.True, $"Enrollment: {enrolled.Error}");

            var vehicleChain   = enrolled.Data!.ToArray();

            Assert.That(vehicleChain[0].CommonName,  Is.EqualTo(pcid.ToString()),
                        "The car's certificate says which car it is.");

            #endregion

            #region ④ ...and publishes it, which is where the ecosystem first hears of the car

            var manufacturer = NewPCPClient([ OPCPRole.OEM ], [ wmi ]);

            var published    = await manufacturer.AddOEMProvCert(
                                         new ProvisioningCertificate(vehicleChain[0],
                                                                     vehicleChain[2],
                                                                     vehicleChain[1])
                                     );

            Assert.That(published.IsSuccess,  Is.True, $"Publication: {published.Error}");

            #endregion

            #region ⑤ A mobility operator finds the car and reads its certificate

            var mobilityOperator = NewPCPClient([ OPCPRole.MO ], [ wmi ]);

            var known            = await mobilityOperator.LookupVehicle(pcid);
            var fetched          = await mobilityOperator.GetOEMProvCert(pcid);

            Assert.Multiple(() => {
                Assert.That(known.  IsSuccess,  Is.True, $"Lookup: {known.Error}");
                Assert.That(fetched.IsSuccess,  Is.True, $"Fetch: {fetched.Error}");
                Assert.That(fetched.Data!.VehicleCertificate.SHA256Fingerprint,
                            Is.EqualTo(vehicleChain[0].SHA256Fingerprint),
                            "The same certificate that was enrolled, all the way through.");
            });

            #endregion

            #region ⑥ It writes a contract with its own PKI, and has the service sign it

            var contract      = pki.IssueContractCertificate(emaId, OwnPKI: true);

            var wrapped       = ContractKeyCrypto.Wrap(contract.PrivateKey,
                                                       fetched.Data!.VehicleCertificate);

            var contractSubCAs = contract.SubCAs.ToArray();

            var signed        = await new CPS_HTTPClient(
                                          baseURL,
                                          TokenFor([ OPCPRole.MO, OPCPRole.MO_ExternalPKI ], null, [ emaId.ProviderId ])
                                      ).SignContractData(
                                          new ContractData(contract.Certificate,
                                                           contractSubCAs[^1],
                                                           wrapped.EncryptedPrivateKey,
                                                           wrapped.DHPublicKey,
                                                           contractSubCAs.Length > 1 ? contractSubCAs[0] : null,
                                                           emaId),
                                          PCID: pcid
                                      );

            Assert.That(signed.IsSuccess,  Is.True, $"Signing: {signed.Error}");

            #endregion

            #region ⑦ A second contract, this time issued by the V2G PKI on the operator's behalf

            var generated = await new CPS_HTTPClient(
                                      baseURL,
                                      TokenFor([ OPCPRole.MO_V2GPKI ], null, [ emaId2.ProviderId ])
                                  ).GenerateSignedContractData(
                                      emaId2,
                                      pcid,
                                      DateTimeOffset.UtcNow,
                                      DateTimeOffset.UtcNow.AddYears(1)
                                  );

            Assert.That(generated.IsSuccess,  Is.True, $"Generation: {generated.Error}");

            #endregion

            #region ⑧ The car plugs in somewhere and gets the contract it charges under

            var chargePointOperator = new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.CPO));

            var installed           = await chargePointOperator.GetSignedContractData(
                                                TestContractDataCodec.EncodeInstallationRequest(pcid)
                                            );

            Assert.That(installed.IsSuccess,  Is.True, $"Installation: {installed.Error}");

            Assert.Multiple(() => {
                Assert.That(installed.Data!.Installed,  Is.True);
                Assert.That(installed.Data.EMAId,       Is.EqualTo(emaId),
                            "The first contract filed for a car is the one it charges under.");
            });

            #endregion

            #region ⑨ The manufacturer collects the same contract over its own channel - and the car opens it

            var collected    = await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.OEM)).
                                         ProvideSignedContractData(emaId, pcid);

            Assert.That(collected.IsSuccess,  Is.True, $"Collection: {collected.Error}");

            var response     = JObject.Parse(Encoding.UTF8.GetString(collected.Data!.CertificateInstallationRes));

            Assert.That(new TestContractDataCodec().TryReadSignedContractData(
                            Convert.FromBase64String(response.Value<String>("signedContractData")!),
                            out var contractData,
                            out var why),
                        Is.True, why);

            // The end of the road for the private key: wrapped by the provisioning service
            // against the certificate the V2G PKI issued in step ③, carried through two pools,
            // and opened here with the key the manufacturer generated before any of it started.
            var contractKey  = ContractKeyCrypto.Unwrap(
                                   new WrappedContractKey(contractData!.ContractSignatureEncryptedPrivateKey,
                                                          contractData.DHPublicKey),
                                   vehicleKeyPair.Private,
                                   vehicleChain[0]
                               );

            Assert.Multiple(() => {
                Assert.That(contractKey,            Is.Not.Empty);
                Assert.That(contractData.Contract,  Is.EqualTo(emaId));
            });

            #endregion

            #region ⑩ The driver switches to the other contract

            var switched  = await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.OEM)).SetDefaultContract(pcid, emaId2);

            Assert.That(switched.IsSuccess,  Is.True, $"Switch: {switched.Error}");

            var pluggedIn = await chargePointOperator.GetSignedContractData(
                                      TestContractDataCodec.EncodeInstallationRequest(pcid)
                                  );

            Assert.That(pluggedIn.Data!.EMAId,  Is.EqualTo(emaId2),
                        "What a car charges under is the manufacturer's to decide, and it decided.");

            #endregion

            #region ⑪ The car is sold, and everything written for it goes away

            var contractsBefore = await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.OEM)).GetContracts(pcid);

            await manufacturer.DeleteOEMProvCert(pcid);

            var contractsAfter  = await new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.OEM)).GetContracts(pcid);
            var stillKnown      = await mobilityOperator.LookupVehicle(pcid);

            Assert.Multiple(() => {
                Assert.That(contractsBefore.Data,       Has.Exactly(2).Items);
                Assert.That(contractsAfter. Data,       Is.Empty,
                            "A car that cannot prove it is that car has no use for contracts.");
                Assert.That(stillKnown.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
            });

            #endregion

            #region ⑫ ...and the partner backend heard every step of it, signed

            await webhookAPI.Delivery.WhenIdle(TimeSpan.FromSeconds(20));

            Assert.Multiple(() => {

                Assert.That(Heard(WebhookEventType.RootCertificateAdded),            Is.EqualTo(3),  "three anchors");
                Assert.That(Heard(WebhookEventType.ContractCreated),                 Is.EqualTo(2),  "two contracts");
                Assert.That(Heard(WebhookEventType.ContractDeliveredToOEM),          Is.EqualTo(2),  "two installations");
                Assert.That(Heard(WebhookEventType.ProvisioningCertificateDeleted),  Is.EqualTo(1),  "one car forgotten");
                Assert.That(Heard(WebhookEventType.ContractDeleted),                 Is.EqualTo(2),  "and both its contracts with it");

            });

            #endregion

        }

        #endregion

    }

}
