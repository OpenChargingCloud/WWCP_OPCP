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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// The Contract Certificate Pool: where a car that plugs in finds out what it charges under.
    /// </summary>
    [TestFixture]
    public class CCPTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly PCID    pcid    = PCID.  Parse("ECD12345671234567");
        private static readonly EMA_Id  emaId   = EMA_Id.Parse("DEECD123456789");
        private static readonly EMA_Id  emaId2  = EMA_Id.Parse("DEECD987654321");

        private IssuedCertificate vehicle = null!;

        [SetUp]
        public void IssueVehicle()
        {
            vehicle = pki.IssueProvisioningCertificate(pcid);
        }

        private CCP_HTTPClient Signer()
            => new (baseURL, TokenFor(OPCPRole.CPS));

        private CCP_HTTPClient ChargePointOperator()
            => new (baseURL, TokenFor(OPCPRole.CPO));

        private CCP_HTTPClient Manufacturer()
            => new (baseURL, TokenFor(OPCPRole.OEM));

        private CCP_HTTPClient MobilityOperator()
            => new (baseURL, TokenFor([ OPCPRole.MO ], null, [ emaId.ProviderId ]));

        private Byte[] PlugIn(params EMA_Id[] Preferred)
            => TestContractDataCodec.EncodeInstallationRequest(pcid, PrioritizedEMAIds: Preferred);

        #endregion


        #region A_car_that_plugs_in_gets_the_contract_that_was_waiting_for_it()

        /// <summary>
        /// The whole point of the protocol, in one test: a provisioning service files a contract,
        /// a car plugs in, and what comes back is that contract.
        /// </summary>
        [Test]
        public async Task A_car_that_plugs_in_gets_the_contract_that_was_waiting_for_it()
        {

            var contract  = NewContract(emaId, vehicle);
            var filed     = await Signer().AddSignedContractData(contract);

            Assert.That(filed.IsSuccess,  Is.True, filed.Error?.ToString());

            var installed = await ChargePointOperator().GetSignedContractData(PlugIn());

            Assert.That(installed.IsSuccess,  Is.True, installed.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(installed.Data!.Installed,  Is.True);
                Assert.That(installed.Data.EMAId,       Is.EqualTo(emaId));
                Assert.That(installed.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.OK));
                Assert.That(installed.Data.CpsV2GRootCertificateFingerprint,
                            Is.EqualTo(pki.V2GRoot.Certificate.SHA256Fingerprint));
            });

        }

        #endregion

        #region The_contract_the_car_receives_carries_a_key_only_that_car_can_unwrap()

        /// <summary>
        /// A contract certificate is worth nothing without its private key, and the key travels
        /// across a charging station that must not learn it. This follows it the whole way: the
        /// provisioning service wraps it against the vehicle's provisioning certificate, and the
        /// vehicle - and nobody else - unwraps it at the far end.
        /// </summary>
        [Test]
        public async Task The_contract_the_car_receives_carries_a_key_only_that_car_can_unwrap()
        {

            var contract   = NewContract(emaId, vehicle);
            await Signer().AddSignedContractData(contract);

            var installed  = await ChargePointOperator().GetSignedContractData(PlugIn());

            Assert.That(installed.IsSuccess,  Is.True, installed.Error?.ToString());

            #region Unpack what came back, as the car would

            var response   = JObject.Parse(Encoding.UTF8.GetString(installed.Data!.CertificateInstallationRes));
            var signed     = Convert.FromBase64String(response.Value<String>("signedContractData")!);

            Assert.That(new TestContractDataCodec().TryReadSignedContractData(signed, out var contractData, out var why),
                        Is.True, why);

            #endregion

            var unwrapped  = ContractKeyCrypto.Unwrap(
                                 new WrappedContractKey(contractData!.ContractSignatureEncryptedPrivateKey,
                                                        contractData.DHPublicKey),
                                 vehicle.PrivateKey,
                                 vehicle.Certificate
                             );

            // Another car cannot: its provisioning key reaches a different shared secret.
            var otherCar   = pki.IssueProvisioningCertificate(PCID.Parse("ECD99999999999999"));

            Assert.Multiple(() => {

                Assert.That(contractData.Contract,             Is.EqualTo(emaId));
                Assert.That(unwrapped,                         Is.Not.Empty);
                Assert.That(contractData.ContractCertificate.CommonName,  Is.EqualTo(emaId.ToString()));

                Assert.That(() => ContractKeyCrypto.Unwrap(
                                      new WrappedContractKey(contractData.ContractSignatureEncryptedPrivateKey,
                                                             contractData.DHPublicKey),
                                      otherCar.PrivateKey,
                                      otherCar.Certificate),
                            Throws.Exception,
                            "Only the car the contract was wrapped for can unwrap it.");

            });

        }

        #endregion

        #region A_car_with_no_contract_gets_an_answer_it_can_still_pass_on()

        /// <summary>
        /// The polymorphic 404: the status says not-found, and the body is nevertheless a
        /// perfectly good ISO 15118 response - because the charging station relaying it speaks
        /// ISO 15118, not HTTP, and has to be handed something it can give the car.
        /// </summary>
        [Test]
        public async Task A_car_with_no_contract_gets_an_answer_it_can_still_pass_on()
        {

            var response = await ChargePointOperator().GetSignedContractData(PlugIn());

            Assert.Multiple(() => {

                // Not an error as far as the client is concerned: there is a readable answer.
                Assert.That(response.IsSuccess,       Is.True, response.Error?.ToString());
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));

                Assert.That(response.Data!.Installed,  Is.False, "But nothing was installed.");
                Assert.That(response.Data.EMAId,       Is.Null);

                var iso = JObject.Parse(Encoding.UTF8.GetString(response.Data.CertificateInstallationRes));
                Assert.That(iso.Value<String>("responseCode"),  Is.EqualTo("FAILED"));
                Assert.That(iso.Value<String>("reason"),        Does.Contain("not found"));

            });

        }

        #endregion

        #region Asking_not_to_get_an_ISO_answer_gets_a_plain_refusal_instead()

        [Test]
        public async Task Asking_not_to_get_an_ISO_answer_gets_a_plain_refusal_instead()
        {

            var response = await ChargePointOperator().GetSignedContractData(PlugIn(),
                                                                             AlwaysReturnEXI: false);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(response.Error!.FirstMessage,  Is.EqualTo("Contract or Vehicle not found."));
                Assert.That(response.TraceId,              Is.Not.Null);
            });

        }

        #endregion

        #region A_car_gets_the_contract_it_asked_for_and_otherwise_its_default()

        [Test]
        public async Task A_car_gets_the_contract_it_asked_for_and_otherwise_its_default()
        {

            var signer = Signer();

            await signer.AddSignedContractData(NewContract(emaId,  vehicle));
            await signer.AddSignedContractData(NewContract(emaId2, vehicle));

            var cpo        = ChargePointOperator();

            var preferred  = await cpo.GetSignedContractData(PlugIn(emaId2));
            var noOpinion  = await cpo.GetSignedContractData(PlugIn());

            Assert.Multiple(() => {
                Assert.That(preferred.Data!.EMAId,  Is.EqualTo(emaId2), "What the car asked for.");
                Assert.That(noOpinion.Data!.EMAId,  Is.EqualTo(emaId),  "The first one filed is the default.");
            });

        }

        #endregion

        #region A_manufacturer_can_change_which_contract_is_the_default()

        [Test]
        public async Task A_manufacturer_can_change_which_contract_is_the_default()
        {

            var signer = Signer();

            await signer.AddSignedContractData(NewContract(emaId,  vehicle));
            await signer.AddSignedContractData(NewContract(emaId2, vehicle));

            var changed  = await Manufacturer().SetDefaultContract(pcid, emaId2);
            var chosen   = await ChargePointOperator().GetSignedContractData(PlugIn());

            Assert.Multiple(() => {
                Assert.That(changed.IsSuccess,   Is.True, changed.Error?.ToString());
                Assert.That(chosen.Data!.EMAId,  Is.EqualTo(emaId2));
            });

        }

        #endregion

        #region Deleting_the_default_leaves_the_car_without_one_and_says_so()

        /// <summary>
        /// The specification is deliberate here: no other contract is promoted, because choosing
        /// which contract a car charges under is not the pool's decision. The manufacturer is
        /// told instead.
        /// </summary>
        [Test]
        public async Task Deleting_the_default_leaves_the_car_without_one_and_says_so()
        {

            var signer     = Signer();
            var announced  = new List<(PCID, EMA_Id)>();

            Task OnLost(PCID pcid, EMA_Id emaId)
            {
                announced.Add((pcid, emaId));
                return Task.CompletedTask;
            }

            ccpAPI.OnDefaultContractLost += OnLost;

            try
            {

                await signer.AddSignedContractData(NewContract(emaId,  vehicle));
                await signer.AddSignedContractData(NewContract(emaId2, vehicle));

                var deleted   = await MobilityOperator().DeleteSignedContractData(emaId);
                var plugIn    = await ChargePointOperator().GetSignedContractData(PlugIn());
                var remaining = await Manufacturer().GetContracts(pcid);

                Assert.Multiple(() => {

                    Assert.That(deleted.IsSuccess,   Is.True, deleted.Error?.ToString());
                    Assert.That(announced,           Is.EqualTo(new[] { (pcid, emaId) }));

                    // The other contract is still there and is still not the default.
                    Assert.That(remaining.Data,      Has.Exactly(1).Items);
                    Assert.That(remaining.Data!.First().Value<Boolean>("defaultContract"),  Is.False);

                    Assert.That(plugIn.Data!.Installed,  Is.False, "So a car that expresses no preference gets nothing.");

                });

            }
            finally
            {
                ccpAPI.OnDefaultContractLost -= OnLost;
            }

        }

        #endregion


        #region A_contract_can_be_looked_up_and_listed()

        [Test]
        public async Task A_contract_can_be_looked_up_and_listed()
        {

            await Signer().AddSignedContractData(NewContract(emaId, vehicle));

            var looked  = await ChargePointOperator().LookupContract(emaId);
            var listed  = await Manufacturer().GetContracts(pcid);

            Assert.Multiple(() => {

                Assert.That(looked.IsSuccess,  Is.True, looked.Error?.ToString());
                Assert.That(looked.Data,       Has.Exactly(1).Items);

                var contract = looked.Data!.First();

                Assert.That(contract.Value<String> ("emaid"),            Is.EqualTo(emaId.ToString()));
                Assert.That(contract.Value<String> ("pcid"),             Is.EqualTo(pcid. ToString()));
                Assert.That(contract.Value<Boolean>("defaultContract"),  Is.True);

                // The pool read these out of what the provisioning service signed; nothing in
                // the request that stored it said them.
                Assert.That(contract.Value<String>("contractCertificate"),  Is.Not.Null.And.Not.Empty);
                Assert.That(contract.Value<String>("certValidFrom"),        Is.Not.Null);
                Assert.That(contract.Value<String>("certValidTo"),          Is.Not.Null);

                Assert.That(listed.Data,  Has.Exactly(1).Items);

            });

        }

        #endregion

        #region A_manufacturer_can_fetch_a_prepared_response_for_one_contract()

        [Test]
        public async Task A_manufacturer_can_fetch_a_prepared_response_for_one_contract()
        {

            await Signer().AddSignedContractData(NewContract(emaId, vehicle));

            var provided  = await Manufacturer().ProvideSignedContractData(emaId, pcid);
            var mismatch  = await Manufacturer().ProvideSignedContractData(emaId, PCID.Parse("ECD99999999999999"));

            Assert.Multiple(() => {
                Assert.That(provided.IsSuccess,               Is.True, provided.Error?.ToString());
                Assert.That(provided.Data!.CertificateInstallationRes,  Is.Not.Empty);
                Assert.That(mismatch.HTTPStatusCode,          Is.EqualTo(HTTPStatusCode.NotFound),
                            "A contract belongs to one vehicle, and asking for it under another finds nothing.");
            });

        }

        #endregion

        #region An_unsigned_contract_is_refused()

        /// <summary>
        /// The pool reads what it is handed, both to learn what it is holding and to check the
        /// signature. Storing something unverifiable would mean handing a car data it will refuse.
        /// </summary>
        [Test]
        public async Task An_unsigned_contract_is_refused()
        {

            var contract = NewContract(emaId, vehicle);

            var tampered = new SignedContractData(
                               contract.EMAId,
                               contract.PCID,
                               Encoding.UTF8.GetBytes("{\"payload\":\"\",\"signature\":\"\"}"),
                               contract.XSDMsgDefNamespace
                           );

            var response = await Signer().AddSignedContractData(tampered);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,       Is.False);
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
            });

        }

        #endregion

        #region Nonsense_in_place_of_a_request_is_refused()

        [Test]
        public async Task Nonsense_in_place_of_a_request_is_refused()
        {

            var response = await ChargePointOperator().GetSignedContractData("this is not a request"u8.ToArray());

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Is.EqualTo("EXI format is invalid!"));
            });

        }

        #endregion


        #region Depublishing_a_vehicle_takes_its_contracts_with_it()

        /// <summary>
        /// The cascade from the provisioning certificate pool. A car whose provisioning
        /// certificate is gone can no longer prove it is the car these contracts were written
        /// for, so leaving them would leave them to fail at a charging station instead.
        /// </summary>
        [Test]
        public async Task Depublishing_a_vehicle_takes_its_contracts_with_it()
        {

            await SeedRootCertificates();

            var manufacturer = NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]);

            await manufacturer.AddOEMProvCert(
                      new ProvisioningCertificate(vehicle.Certificate,
                                                  pki.OEMSubCA1.Certificate,
                                                  pki.OEMSubCA2.Certificate));

            await Signer().AddSignedContractData(NewContract(emaId, vehicle));

            var before = await Manufacturer().GetContracts(pcid);

            await manufacturer.DeleteOEMProvCert(pcid);

            var after  = await Manufacturer().GetContracts(pcid);

            Assert.Multiple(() => {
                Assert.That(before.Data,  Has.Exactly(1).Items);
                Assert.That(after.Data,   Is.Empty, "The contracts went with the vehicle.");
            });

        }

        #endregion

        #region A_new_key_pair_takes_the_old_contracts_with_it()

        /// <summary>
        /// The workshop case. Every contract was wrapped against the old key, so none of them can
        /// be unwrapped by the car any more.
        /// </summary>
        [Test]
        public async Task A_new_key_pair_takes_the_old_contracts_with_it()
        {

            await SeedRootCertificates();

            var manufacturer = NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]);

            await manufacturer.AddOEMProvCert(
                      new ProvisioningCertificate(vehicle.Certificate,
                                                  pki.OEMSubCA1.Certificate,
                                                  pki.OEMSubCA2.Certificate));

            await Signer().AddSignedContractData(NewContract(emaId, vehicle));

            var before      = await Manufacturer().GetContracts(pcid);

            // The same car, a new key pair.
            var replacement = pki.IssueProvisioningCertificate(pcid);

            await manufacturer.AddOEMProvCert(
                      new ProvisioningCertificate(replacement.Certificate,
                                                  pki.OEMSubCA1.Certificate,
                                                  pki.OEMSubCA2.Certificate));

            var after       = await Manufacturer().GetContracts(pcid);

            Assert.Multiple(() => {
                Assert.That(before.Data,  Has.Exactly(1).Items);
                Assert.That(after.Data,   Is.Empty, "Nothing wrapped against the old key survives.");
            });

        }

        #endregion


        #region Only_a_charge_point_operator_may_answer_a_plugged_in_car(Role)

        [TestCase("OEM")]
        [TestCase("MO")]
        [TestCase("CPS")]
        public async Task Only_a_charge_point_operator_may_answer_a_plugged_in_car(String Role)
        {

            var client   = new CCP_HTTPClient(baseURL, TokenFor(OPCPRole.Parse(Role)));
            var response = await client.GetSignedContractData(PlugIn());

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));

        }

        #endregion

        #region Only_a_provisioning_service_may_file_contracts()

        [Test]
        public async Task Only_a_provisioning_service_may_file_contracts()
        {

            var contract = NewContract(emaId, vehicle);

            var byOperator = await MobilityOperator().  AddSignedContractData(contract);
            var byMaker    = await Manufacturer().      AddSignedContractData(contract);

            Assert.Multiple(() => {
                Assert.That(byOperator.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(byMaker.   HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region An_operator_may_only_delete_its_own_contracts()

        [Test]
        public async Task An_operator_may_only_delete_its_own_contracts()
        {

            await Signer().AddSignedContractData(NewContract(emaId, vehicle));

            var stranger = new CCP_HTTPClient(baseURL,
                                              TokenFor([ OPCPRole.MO ], null, [ Provider_Id.Parse("DEXYZ") ]));

            var refused  = await stranger.       DeleteSignedContractData(emaId);
            var allowed  = await MobilityOperator().DeleteSignedContractData(emaId);

            Assert.Multiple(() => {
                Assert.That(refused.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(allowed.IsSuccess,       Is.True, allowed.Error?.ToString());
            });

        }

        #endregion

        #region An_unknown_contract_is_a_404()

        [Test]
        public async Task An_unknown_contract_is_a_404()
        {

            var looked  = await ChargePointOperator().LookupContract(EMA_Id.Parse("DEECD000000000"));
            var deleted = await MobilityOperator().   DeleteSignedContractData(EMA_Id.Parse("DEECD000000000"));

            Assert.Multiple(() => {
                Assert.That(looked.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(deleted.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(deleted.Error!.FirstMessage,  Does.Contain("not found"));
            });

        }

        #endregion

    }

}
