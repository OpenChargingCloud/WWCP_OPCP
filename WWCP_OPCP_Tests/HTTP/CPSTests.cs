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
    /// The Certificate Provisioning Service: the only signature a vehicle will accept on a
    /// contract, and therefore the only way anything gets into the contract certificate pool.
    /// </summary>
    [TestFixture]
    public class CPSTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly PCID    pcid    = PCID.  Parse("ECD12345671234567");
        private static readonly PCID    pcid2   = PCID.  Parse("ECD76543217654321");
        private static readonly EMA_Id  emaId   = EMA_Id.Parse("DEECD123456789");
        private static readonly EMA_Id  emaId2  = EMA_Id.Parse("DEECD987654321");

        private IssuedCertificate vehicle = null!;

        /// <summary>
        /// A car that exists, an ecosystem that knows the three roots, and the car published in
        /// the provisioning certificate pool - which is where the contract provisioning service
        /// looks for the key it wraps a contract against.
        /// </summary>
        [SetUp]
        public async Task PrepareEcosystem()
        {

            vehicle = pki.IssueProvisioningCertificate(pcid);

            await SeedRootCertificates();

            await NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]).AddOEMProvCert(
                      new ProvisioningCertificate(vehicle.Certificate,
                                                  pki.OEMSubCA1.Certificate,
                                                  pki.OEMSubCA2.Certificate));

        }

        /// <summary>
        /// The contracts these tests file are filed through the service rather than by hand, so
        /// the fixture's own bookkeeping does not know about them.
        /// </summary>
        [TearDown]
        public async Task RemoveContracts()
        {
            foreach (var contract in new[] { emaId, emaId2 })
                await ccpAPI.Store.Remove(contract);
        }


        private CPS_HTTPClient MobilityOperator(EMA_Id? For = null)
            => new (baseURL, TokenFor([ OPCPRole.MO, OPCPRole.MO_ExternalPKI ],
                                      null,
                                      [ (For ?? emaId).ProviderId ]));

        private CPS_HTTPClient MobilityOperatorWithoutPKI(EMA_Id? For = null)
            => new (baseURL, TokenFor([ OPCPRole.MO_V2GPKI ],
                                      null,
                                      [ (For ?? emaId).ProviderId ]));

        private CCP_HTTPClient ChargePointOperator()
            => new (baseURL, TokenFor(OPCPRole.CPO));

        /// <summary>
        /// Contract data as an operator with its own PKI brings it: a contract certificate it
        /// issued itself, and the contract's private key already wrapped for one car.
        /// </summary>
        private ContractData OwnContractData(EMA_Id             EMAId,
                                             IssuedCertificate  Vehicle,
                                             Boolean            OwnPKI   = true)
        {

            var contract  = pki.IssueContractCertificate(EMAId, OwnPKI);
            var wrapped   = ContractKeyCrypto.Wrap(contract.PrivateKey, Vehicle.Certificate);
            var subCAs    = contract.SubCAs.ToArray();

            return new ContractData(
                       contract.Certificate,
                       subCAs[^1],
                       wrapped.EncryptedPrivateKey,
                       wrapped.DHPublicKey,
                       subCAs.Length > 1 ? subCAs[0] : null,
                       EMAId
                   );

        }

        /// <summary>
        /// Read the contract out of what the service signed, which is also the check that the
        /// signature is genuine - the codec refuses to read data it cannot verify.
        /// </summary>
        private static ContractData Read(Byte[] SignedData)
        {

            Assert.That(new TestContractDataCodec().TryReadSignedContractData(SignedData, out var contractData, out var why),
                        Is.True, why);

            return contractData!;

        }

        #endregion


        #region An_operator_with_its_own_PKI_gets_its_contract_signed()

        /// <summary>
        /// The plain case: an operator brings a contract it issued itself and gets back something
        /// a vehicle will accept. Nothing is filed, because the request named no vehicle.
        /// </summary>
        [Test]
        public async Task An_operator_with_its_own_PKI_gets_its_contract_signed()
        {

            var signed = await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle));

            Assert.That(signed.IsSuccess,  Is.True, signed.Error?.ToString());

            Assert.Multiple(() => {

                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Created));
                Assert.That(signed.Data!.EMAId,     Is.EqualTo(emaId));
                Assert.That(signed.Data.SignedData, Is.Not.Empty);

                // Which V2G root this signature can be verified against - the whole of what an
                // operator needs in order to know whether its cars will accept the result.
                Assert.That(signed.Data.CpsV2GRootCertificateFingerprint,
                            Is.EqualTo(pki.V2GRoot.Certificate.SHA256Fingerprint));

                Assert.That(signed.Data.CpsRootDistinguishedName,
                            Is.EqualTo(pki.V2GRoot.Certificate.SubjectName));

                Assert.That(signed.Data.PCID,       Is.Null, "No vehicle was named.");

            });

            Assert.That(await ccpAPI.Store.Get(emaId),  Is.Null,
                        "Without a PCID nothing is filed - the operator files it itself.");

        }

        #endregion

        #region Naming_the_vehicle_is_what_files_the_contract_in_the_pool()

        /// <summary>
        /// The same request with a PCID in it, which is the whole difference between this
        /// operation and the two it replaces - and the car it names finds the contract waiting
        /// the next time it plugs in.
        /// </summary>
        [Test]
        public async Task Naming_the_vehicle_is_what_files_the_contract_in_the_pool()
        {

            var signed    = await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle),
                                                                      PCID: pcid);

            Assert.That(signed.IsSuccess,  Is.True, signed.Error?.ToString());
            Assert.That(signed.Data!.PCID, Is.EqualTo(pcid));

            // All the way through: the car plugs in at a charging station and gets what the
            // provisioning service signed a moment ago.
            var installed = await ChargePointOperator().GetSignedContractData(
                                      TestContractDataCodec.EncodeInstallationRequest(pcid)
                                  );

            Assert.That(installed.IsSuccess,  Is.True, installed.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(installed.Data!.Installed,  Is.True);
                Assert.That(installed.Data.EMAId,       Is.EqualTo(emaId));
            });

        }

        #endregion

        #region What_comes_back_is_signed_by_the_certificate_the_service_publishes()

        /// <summary>
        /// A vehicle checks two things about contract data: that the signature is genuine, and
        /// that the certificate it was made under chains to a V2G root the car trusts. Both are
        /// checked here, against the signer the service publishes for anybody to look up.
        /// </summary>
        [Test]
        public async Task What_comes_back_is_signed_by_the_certificate_the_service_publishes()
        {

            var signed = await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle));

            Assert.That(signed.IsSuccess,  Is.True, signed.Error?.ToString());

            Assert.That(TestContractDataCodec.VerifySignedContractData(signed.Data!.SignedData,
                                                                       out var signerCertificate,
                                                                       out var why),
                        Is.True, why);

            var published = await MobilityOperator().GetAllCpsSigners();

            Assert.That(published.IsSuccess,  Is.True, published.Error?.ToString());

            var signer    = published.Data!.First();

            Assert.Multiple(() => {

                Assert.That(signerCertificate!.SHA256Fingerprint,
                            Is.EqualTo(cpsSigner.Certificate.SHA256Fingerprint));

                Assert.That(signer.Certificate.SHA256Fingerprint,
                            Is.EqualTo(signerCertificate.SHA256Fingerprint),
                            "The published signer is the one that signed.");

                // And the path from it to a root the ecosystem admitted.
                Assert.That(PnCChainValidator.Validate(signerCertificate,
                                                       [ signer.SubCA2Certificate!, signer.SubCA1Certificate! ],
                                                       [ pki.V2GRoot.Certificate ]).IsValid,
                            Is.True);

            });

        }

        #endregion

        #region The_contract_it_signed_still_only_opens_for_the_car_it_was_wrapped_for()

        /// <summary>
        /// The provisioning service never sees the contract's private key in the clear and does
        /// not need to: it signs around it. What it signed still unwraps for exactly one car.
        /// </summary>
        [Test]
        public async Task The_contract_it_signed_still_only_opens_for_the_car_it_was_wrapped_for()
        {

            var signed       = await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle),
                                                                         PCID: pcid);

            Assert.That(signed.IsSuccess,  Is.True, signed.Error?.ToString());

            var contractData = Read(signed.Data!.SignedData);

            var unwrapped    = ContractKeyCrypto.Unwrap(
                                   new WrappedContractKey(contractData.ContractSignatureEncryptedPrivateKey,
                                                          contractData.DHPublicKey),
                                   vehicle.PrivateKey,
                                   vehicle.Certificate
                               );

            var otherCar     = pki.IssueProvisioningCertificate(pcid2);

            Assert.Multiple(() => {

                Assert.That(unwrapped,              Is.Not.Empty);
                Assert.That(contractData.Contract,  Is.EqualTo(emaId));

                Assert.That(() => ContractKeyCrypto.Unwrap(
                                      new WrappedContractKey(contractData.ContractSignatureEncryptedPrivateKey,
                                                             contractData.DHPublicKey),
                                      otherCar.PrivateKey,
                                      otherCar.Certificate),
                            Throws.Exception);

            });

        }

        #endregion


        #region A_contract_already_filed_for_one_car_cannot_be_filed_for_another()

        /// <summary>
        /// A contract belongs to one car. Letting a second one claim an EMAID already in use
        /// would take the contract away from the first, which nobody asked for.
        /// </summary>
        [Test]
        public async Task A_contract_already_filed_for_one_car_cannot_be_filed_for_another()
        {

            await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle), PCID: pcid);

            var otherCar = pki.IssueProvisioningCertificate(pcid2);

            var again    = await MobilityOperator().SignContractData(OwnContractData(emaId, otherCar),
                                                                     PCID: pcid2);

            Assert.Multiple(() => {

                Assert.That(again.IsSuccess,       Is.False);
                Assert.That(again.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(again.Error?.ErrorMessages,
                            Does.Contain("Invalid Tupple - EMAID is already used by other PCID."));

            });

        }

        #endregion

        #region A_contract_that_anchors_nowhere_this_ecosystem_knows_is_not_signed()

        /// <summary>
        /// The signature is what makes a contract acceptable, so it is not given to a chain that
        /// reaches no root this ecosystem has admitted. Signing that would be this service
        /// vouching for an authority nobody here has any reason to believe.
        /// </summary>
        [Test]
        public async Task A_contract_that_anchors_nowhere_this_ecosystem_knows_is_not_signed()
        {

            // The operator's own root, withdrawn from the pool after the contract was issued
            // under it.
            foreach (var rootCertificate in await rcpAPI.Store.GetAll(RootCertificateType.MO))
                if (rootCertificate.Id.HasValue)
                    await rcpAPI.Store.Remove(rootCertificate.Id.Value);

            var signed = await MobilityOperator().SignContractData(OwnContractData(emaId, vehicle));

            Assert.Multiple(() => {
                Assert.That(signed.IsSuccess,       Is.False);
                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
            });

        }

        #endregion

        #region An_EMAID_that_contradicts_the_contract_certificate_is_refused()

        /// <summary>
        /// The specification says the EMAID has to fit the common name of the contract
        /// certificate. Where a request states both and they disagree, one of them is a mistake,
        /// and signing either would make it permanent.
        /// </summary>
        [Test]
        public async Task An_EMAID_that_contradicts_the_contract_certificate_is_refused()
        {

            var body     = new SignedContractDataRequest(
                               OwnContractData(emaId, vehicle),
                               EMAId: emaId2
                           ).ToJSON();

            // The typed client derives the EMAID from the certificate, so this one has to be
            // written by hand to disagree with it at all.
            body["emaid"] = emaId2.ToString();

            var response = await new RawOPCPClient(baseURL, TokenFor([ OPCPRole.MO ], null, [ emaId.ProviderId ])).SendRaw(
                                     HTTPMethod.PUT,
                                     $"{CPS_HTTPClient.URLPrefix}/contractData/signed",
                                     body
                                 );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));

        }

        #endregion

        #region Naming_a_root_this_service_cannot_sign_under_is_refused()

        /// <summary>
        /// An operator that asks for a particular V2G root is saying which of its cars have to be
        /// able to verify the result. Signing under a different one instead would produce contract
        /// data those cars reject, so the request is refused rather than quietly answered.
        /// </summary>
        [Test]
        public async Task Naming_a_root_this_service_cannot_sign_under_is_refused()
        {

            var signed = await MobilityOperator().SignContractData(
                                   OwnContractData(emaId, vehicle),
                                   CpsV2GRootCertificateFingerprint: pki.UntrustedRoot.Certificate.SHA256Fingerprint
                               );

            Assert.Multiple(() => {
                Assert.That(signed.IsSuccess,       Is.False);
                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
            });

        }

        #endregion


        #region The_deprecated_operation_that_only_signs_still_works()

        /// <summary>
        /// Deprecated by the specification and still operated, so still implemented - with the
        /// nested contract data it takes, and answering 200 rather than 201 because it created
        /// nothing.
        /// </summary>
        [Test]
        public async Task The_deprecated_operation_that_only_signs_still_works()
        {

#pragma warning disable CS0618 // Deprecated on purpose: this test is what says it still works.
            var signed = await MobilityOperator().CreateSignedContractData(
                                   new SignedContractDataRequest(
                                       OwnContractData(emaId, vehicle),
                                       PCID: pcid
                                   ));
#pragma warning restore CS0618

            Assert.That(signed.IsSuccess,  Is.True, signed.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));
                Assert.That(signed.Data!.EMAId,     Is.EqualTo(emaId));
            });

            Assert.That(await ccpAPI.Store.Get(emaId),  Is.Null,
                        "This one never files anything, even with a PCID.");

        }

        #endregion

        #region The_deprecated_operation_that_signs_and_files_still_works()

        /// <summary>
        /// Its replacement does the same thing when the request names a vehicle, and answers with
        /// the signature rather than with an empty body.
        /// </summary>
        [Test]
        public async Task The_deprecated_operation_that_signs_and_files_still_works()
        {

#pragma warning disable CS0618 // Deprecated on purpose: this test is what says it still works.
            var forwarded = await MobilityOperator().CreateAndForwardSignedContractData(
                                      new SignedContractDataRequest(
                                          OwnContractData(emaId, vehicle),
                                          PCID: pcid
                                      ));
#pragma warning restore CS0618

            Assert.That(forwarded.IsSuccess,  Is.True, forwarded.Error?.ToString());

            var filed = await ccpAPI.Store.Get(emaId);

            Assert.Multiple(() => {
                Assert.That(forwarded.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Created));
                Assert.That(filed,                     Is.Not.Null);
                Assert.That(filed!.PCID,               Is.EqualTo(pcid));
            });

        }

        #endregion

        #region The_deprecated_operations_read_the_nested_contract_data()

        /// <summary>
        /// The shape they take is the older one, with the certificates nested inside a
        /// contractSignatureCertChain and the sub-CAs listed deepest first. Sent by hand, because
        /// what is being tested is that the wire form is understood.
        /// </summary>
        [Test]
        public async Task The_deprecated_operations_read_the_nested_contract_data()
        {

            var body     = new SignedContractDataRequest(
                               OwnContractData(emaId, vehicle),
                               PCID: pcid
                           ).ToJSON(Nested: true);

            Assert.That(body["contractData"]?["contractSignatureCertChain"],  Is.Not.Null,
                        "The deprecated shape nests the chain.");

            var response = await new RawOPCPClient(baseURL, TokenFor([ OPCPRole.MO ], null, [ emaId.ProviderId ])).SendRaw(
                                     HTTPMethod.PUT,
                                     $"{CPS_HTTPClient.URLPrefix}/signedContractData",
                                     body
                                 );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));

        }

        #endregion


        #region An_operator_without_a_PKI_of_its_own_only_describes_the_contract()

        /// <summary>
        /// The other half of the service, and the only place in the protocol where all three
        /// pools meet: the car comes from the provisioning certificate pool, the contract
        /// certificate is issued here under the V2G root, and the result goes into the contract
        /// certificate pool - from where that car collects it the next time it plugs in.
        /// </summary>
        [Test]
        public async Task An_operator_without_a_PKI_of_its_own_only_describes_the_contract()
        {

            var generated = await MobilityOperatorWithoutPKI().GenerateSignedContractData(
                                      emaId,
                                      pcid,
                                      DateTimeOffset.UtcNow,
                                      DateTimeOffset.UtcNow.AddYears(1)
                                  );

            Assert.That(generated.IsSuccess,  Is.True, generated.Error?.ToString());
            Assert.That(generated.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Created));

            var filed        = await ccpAPI.Store.Get(emaId);

            Assert.That(filed,  Is.Not.Null, "The service filed what it generated.");

            var contractData = Read(filed!.SignedContractDataXML);

            // The car can open it, which is the point: the service wrapped the private key of a
            // certificate it had just issued against the key in the car's own certificate.
            var unwrapped    = ContractKeyCrypto.Unwrap(
                                   new WrappedContractKey(contractData.ContractSignatureEncryptedPrivateKey,
                                                          contractData.DHPublicKey),
                                   vehicle.PrivateKey,
                                   vehicle.Certificate
                               );

            Assert.Multiple(() => {

                Assert.That(unwrapped,                                    Is.Not.Empty);
                Assert.That(contractData.ContractCertificate.CommonName,  Is.EqualTo(emaId.ToString()));

                // Issued under the mobility operator authority below the V2G root, which is what
                // makes it verifiable by a car that knows nothing about this operator.
                Assert.That(PnCChainValidator.ValidateContractCertificate(contractData.ContractCertificate,
                                                                          contractData.SubCAs,
                                                                          [ pki.V2GRoot.Certificate ],
                                                                          emaId).IsValid,
                            Is.True);

                // Checked to the day rather than to the second: the certificate factory reads
                // its own clock and shifts both boundaries by the local UTC offset, so the exact
                // instant is not this library's to promise. What is promised is that the
                // certificate follows the contract instead of some default lifetime.
                Assert.That(contractData.ContractCertificate.NotAfter,
                            Is.EqualTo(DateTimeOffset.UtcNow.AddYears(1)).Within(TimeSpan.FromDays(1)),
                            "The certificate expires with the contract.");

            });

        }

        #endregion

        #region A_generated_contract_reaches_the_car_that_plugs_in()

        /// <summary>
        /// The same thing from the charging station's side, which is the only side that matters.
        /// </summary>
        [Test]
        public async Task A_generated_contract_reaches_the_car_that_plugs_in()
        {

            await MobilityOperatorWithoutPKI().GenerateSignedContractData(
                      emaId,
                      pcid,
                      DateTimeOffset.UtcNow,
                      DateTimeOffset.UtcNow.AddYears(1)
                  );

            var installed = await ChargePointOperator().GetSignedContractData(
                                      TestContractDataCodec.EncodeInstallationRequest(pcid)
                                  );

            Assert.That(installed.IsSuccess,  Is.True, installed.Error?.ToString());

            Assert.Multiple(() => {
                Assert.That(installed.Data!.Installed,  Is.True);
                Assert.That(installed.Data.EMAId,       Is.EqualTo(emaId));
            });

        }

        #endregion

        #region Generating_for_a_vehicle_the_ecosystem_does_not_know_is_refused()

        /// <summary>
        /// There is nothing to wrap the contract's private key against, so there is no contract
        /// to be had.
        /// </summary>
        [Test]
        public async Task Generating_for_a_vehicle_the_ecosystem_does_not_know_is_refused()
        {

            var generated = await MobilityOperatorWithoutPKI().GenerateSignedContractData(
                                      emaId,
                                      pcid2,
                                      DateTimeOffset.UtcNow,
                                      DateTimeOffset.UtcNow.AddYears(1)
                                  );

            Assert.Multiple(() => {

                Assert.That(generated.IsSuccess,       Is.False);
                Assert.That(generated.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(generated.Error?.ErrorMessages,
                            Does.Contain("The OEM provisioning certificate with the given PCID is not available."));

            });

        }

        #endregion

        #region A_contract_that_has_already_ended_is_refused()

        /// <summary>
        /// The specification's own words for it.
        /// </summary>
        [Test]
        public async Task A_contract_that_has_already_ended_is_refused()
        {

            var generated = await MobilityOperatorWithoutPKI().GenerateSignedContractData(
                                      emaId,
                                      pcid,
                                      DateTimeOffset.UtcNow.AddYears(-2),
                                      DateTimeOffset.UtcNow.AddYears(-1)
                                  );

            Assert.Multiple(() => {

                Assert.That(generated.IsSuccess,       Is.False);
                Assert.That(generated.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(generated.Error?.ErrorMessages,
                            Does.Contain("The given contractEnds date is in the past."));

            });

        }

        #endregion

        #region Generating_the_same_contract_again_renews_it()

        /// <summary>
        /// Calling this again with the same vehicle and contract replaces what was filed before,
        /// which is how a contract is renewed. The car ends up with one contract, under a
        /// certificate it has never seen before.
        /// </summary>
        [Test]
        public async Task Generating_the_same_contract_again_renews_it()
        {

            var operatorWithoutPKI = MobilityOperatorWithoutPKI();

            await operatorWithoutPKI.GenerateSignedContractData(emaId, pcid,
                                                                DateTimeOffset.UtcNow,
                                                                DateTimeOffset.UtcNow.AddMonths(6));

            var first  = Read((await ccpAPI.Store.Get(emaId))!.SignedContractDataXML);

            await operatorWithoutPKI.GenerateSignedContractData(emaId, pcid,
                                                                DateTimeOffset.UtcNow,
                                                                DateTimeOffset.UtcNow.AddYears(2));

            var second = Read((await ccpAPI.Store.Get(emaId))!.SignedContractDataXML);

            var held   = await ccpAPI.Store.GetByVehicle(pcid);

            Assert.Multiple(() => {

                Assert.That(held,  Has.Exactly(1).Items);

                Assert.That(second.ContractCertificate.SHA256Fingerprint,
                            Is.Not.EqualTo(first.ContractCertificate.SHA256Fingerprint),
                            "A renewal is a new certificate.");

                Assert.That(second.ContractCertificate.NotAfter,
                            Is.GreaterThan(first.ContractCertificate.NotAfter));

            });

        }

        #endregion


        #region The_signers_are_published_at_the_path_the_specification_gives_and_at_the_one_it_meant()

        /// <summary>
        /// This one operation sits outside the version prefix that every other operation of this
        /// service carries. That is the specification's own path and plainly one of its
        /// inconsistencies, so both are served.
        /// </summary>
        [Test]
        public async Task The_signers_are_published_at_the_path_the_specification_gives_and_at_the_one_it_meant()
        {

            var raw        = new RawOPCPClient(baseURL, TokenFor(OPCPRole.CPO));

            var unprefixed = await raw.SendRaw(HTTPMethod.GET, "/cps/signer");
            var prefixed   = await raw.SendRaw(HTTPMethod.GET, "/v1/cps/signer");

            Assert.Multiple(() => {
                Assert.That(unprefixed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));
                Assert.That(prefixed.  HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));
            });

            var body = JObject.Parse(Encoding.UTF8.GetString(unprefixed.HTTPBody ?? []));

            Assert.That(CPSEnvelope.TryUnwrapMany(body, out var signers, out var why),  Is.True, why);

            var signer = signers!.First();

            Assert.Multiple(() => {

                Assert.That(signers,                                 Has.Exactly(1).Items);
                Assert.That(signer.CpsDistinguishedName,             Is.EqualTo(cpsSigner.Certificate.SubjectName));
                Assert.That(signer.CpsV2GRootCertificateFingerprint, Is.EqualTo(pki.V2GRoot.Certificate.SHA256Fingerprint));
                Assert.That(signer.CpsRootDistinguishedName,         Is.EqualTo(pki.V2GRoot.Certificate.SubjectName));

                Assert.That(signer.SubCA1Certificate?.CommonName,     Is.EqualTo(pki.CPSSubCA1.Certificate.CommonName));
                Assert.That(signer.SubCA2Certificate?.CommonName,     Is.EqualTo(pki.CPSSubCA2.Certificate.CommonName));

                Assert.That(signer.ValidTo,                           Is.EqualTo(cpsSigner.Certificate.NotAfter));

                // Nothing here is a secret, and there is nowhere for one to hide: the published
                // shape has no field a private key could travel in.
                Assert.That(body.ToString(),                          Does.Not.Contain("PRIVATE"));

            });

        }

        #endregion

        #region Listing_the_signers_still_needs_a_token()

        /// <summary>
        /// Every role may ask which signers there are. Nobody may ask anonymously.
        /// </summary>
        [Test]
        public async Task Listing_the_signers_still_needs_a_token()
        {

            var response = await new RawOPCPClient(baseURL).SendRaw(HTTPMethod.GET, "/cps/signer");

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));

        }

        #endregion


        #region An_operator_may_only_have_its_own_contracts_signed()

        /// <summary>
        /// A token says which e-mobility providers its holder acts for, and a contract belongs to
        /// exactly one of them.
        /// </summary>
        [Test]
        public async Task An_operator_may_only_have_its_own_contracts_signed()
        {

            var stranger = new CPS_HTTPClient(
                               baseURL,
                               TokenFor([ OPCPRole.MO, OPCPRole.MO_ExternalPKI ],
                                        null,
                                        [ Provider_Id.Parse("DEXYZ") ])
                           );

            var signed   = await stranger.SignContractData(OwnContractData(emaId, vehicle));

            Assert.Multiple(() => {
                Assert.That(signed.IsSuccess,       Is.False);
                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region A_charge_point_operator_has_no_business_here()

        /// <summary>
        /// Signing contracts is a mobility operator's business. A charge point operator may look
        /// up the signers and nothing else.
        /// </summary>
        [Test]
        public async Task A_charge_point_operator_has_no_business_here()
        {

            var signed = await new CPS_HTTPClient(baseURL, TokenFor(OPCPRole.CPO)).
                                   SignContractData(OwnContractData(emaId, vehicle));

            Assert.Multiple(() => {
                Assert.That(signed.IsSuccess,       Is.False);
                Assert.That(signed.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region The_two_paths_are_for_two_different_kinds_of_operator()

        /// <summary>
        /// The rights matrix separates them: an operator with a PKI of its own uses the signing
        /// path, one without uses the generating path, and neither may use the other's.
        /// </summary>
        [Test]
        public async Task The_two_paths_are_for_two_different_kinds_of_operator()
        {

            var withoutPKI = await MobilityOperatorWithoutPKI().SignContractData(OwnContractData(emaId, vehicle));

            var withPKI    = await new CPS_HTTPClient(
                                       baseURL,
                                       TokenFor([ OPCPRole.MO_ExternalPKI ], null, [ emaId.ProviderId ])
                                   ).GenerateSignedContractData(emaId, pcid,
                                                                DateTimeOffset.UtcNow,
                                                                DateTimeOffset.UtcNow.AddYears(1));

            Assert.Multiple(() => {
                Assert.That(withoutPKI.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(withPKI.   HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

    }

}
