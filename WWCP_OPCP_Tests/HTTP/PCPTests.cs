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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// The Provisioning Certificate Pool: a manufacturer publishing what a vehicle was born with,
    /// and an operator reading it before writing that vehicle a contract.
    /// </summary>
    [TestFixture]
    public class PCPTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly WMI   ecd   = WMI. Parse("ECD");
        private static readonly PCID  pcid  = PCID.Parse("ECD12345671234567");

        private readonly List<PnCCertificate> revoked = [];

        [SetUp]
        public async Task SeedTrustAnchors()
        {

            foreach (var certificate in revoked)
                oemResponder.Unrevoke(certificate);

            revoked.Clear();

            await SeedRootCertificates();

        }

        /// <summary>A chain for the given vehicle, straight from the manufacturers' hierarchy.</summary>
        private ProvisioningCertificate ChainFor(PCID? PCID = null)
        {

            var issued = pki.IssueProvisioningCertificate(PCID ?? pcid);

            return new ProvisioningCertificate(
                       issued.Certificate,
                       pki.OEMSubCA1.Certificate,
                       pki.OEMSubCA2.Certificate,
                       V2GRootAuthorityKeyIdentifiers: [ "4F:13:33:6B:AE:33:CB:1C" ]
                   );

        }

        private PCP_HTTPClient Manufacturer()
            => NewPCPClient([ OPCPRole.OEM ], [ ecd ]);

        private PCP_HTTPClient Operator()
            => NewPCPClient([ OPCPRole.MO ]);

        #endregion


        #region A_vehicle_is_published_and_read_back()

        [Test]
        public async Task A_vehicle_is_published_and_read_back()
        {

            var chain     = ChainFor();
            var added     = await Manufacturer().AddOEMProvCert(chain);

            Assert.That(added.IsSuccess,  Is.True, added.Error?.ToString());

            var fetched   = await Operator().GetOEMProvCert(pcid);

            Assert.That(fetched.IsSuccess,  Is.True, fetched.Error?.ToString());

            var stored    = fetched.Data!;

            Assert.Multiple(() => {

                // Nothing in the request said which vehicle: the pool read it from the
                // certificate's common name.
                Assert.That(stored.PCID,                Is.EqualTo(pcid));
                Assert.That(stored.VehicleCertificate,  Is.EqualTo(chain.VehicleCertificate));
                Assert.That(stored.SubCA1Certificate,   Is.EqualTo(pki.OEMSubCA1.Certificate));
                Assert.That(stored.SubCA2Certificate,   Is.EqualTo(pki.OEMSubCA2.Certificate));

                // What the pool worked out while validating. The root itself does not travel -
                // the recipient is supposed to already have it from the root certificate pool -
                // so what arrives is what the pool says about it.
                Assert.That(stored.RootCertificate,             Is.Null, "The anchor itself is not on the wire.");
                Assert.That(stored.RootIssuerDistinguishedName, Is.EqualTo(pki.OEMRoot.Certificate.SubjectName));
                Assert.That(stored.RootIssuerSerialNumber,      Is.EqualTo(pki.OEMRoot.Certificate.SerialNumber));
                Assert.That(stored.Fingerprint,                 Is.EqualTo(chain.VehicleCertificate.SHA256Fingerprint));

                // Uppercase hexadecimal with colons, as the specification's own example writes it.
                Assert.That(stored.RootAuthorityKeyIdentifier,  Does.Match("^([0-9A-F]{2}:)+[0-9A-F]{2}$"));

                // What the manufacturer supplied and no certificate states.
                Assert.That(stored.V2GRootAuthorityKeyIdentifiers,  Is.EqualTo(new[] { "4F:13:33:6B:AE:33:CB:1C" }));

            });

        }

        #endregion

        #region A_vehicle_can_be_looked_up_without_being_fetched()

        [Test]
        public async Task A_vehicle_can_be_looked_up_without_being_fetched()
        {

            var operatorClient = Operator();

            var before = await operatorClient.LookupVehicle(pcid);

            await Manufacturer().AddOEMProvCert(ChainFor());

            var after  = await operatorClient.LookupVehicle(pcid);

            Assert.Multiple(() => {
                Assert.That(before.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(after.IsSuccess,        Is.True, after.Error?.ToString());
                Assert.That(after.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.OK));
            });

        }

        #endregion


        #region A_chain_to_a_root_the_ecosystem_never_admitted_is_refused()

        /// <summary>
        /// Step four of the validation: a chain has to reach a manufacturer root this ecosystem
        /// has admitted into its root certificate pool. Everything about this chain is well-formed.
        /// </summary>
        [Test]
        public async Task A_chain_to_a_root_the_ecosystem_never_admitted_is_refused()
        {

            var stranger = pki.IssueUntrusted(pcid.ToString());

            var chain    = new ProvisioningCertificate(
                               stranger.Certificate,
                               pki.OEMSubCA1.Certificate
                           );

            var response = await Manufacturer().AddOEMProvCert(chain);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("neither a trusted root"));
            });

        }

        #endregion

        #region A_revoked_vehicle_certificate_is_refused()

        /// <summary>
        /// Step three: the pool asks the responder about every certificate it is given, and a
        /// revoked one never enters the pool.
        /// </summary>
        [Test]
        public async Task A_revoked_vehicle_certificate_is_refused()
        {

            var chain = ChainFor();

            oemResponder.Revoke(chain.VehicleCertificate, RevocationReason.KeyCompromise);
            revoked.Add(chain.VehicleCertificate);

            var response = await Manufacturer().AddOEMProvCert(chain);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("revoked"));
            });

        }

        #endregion

        #region A_certificate_revoked_after_publication_is_no_longer_served()

        /// <summary>
        /// The pool checks on the way out as well as on the way in. An operator about to write a
        /// contract must not be handed a certificate that stopped being usable in the meantime.
        /// </summary>
        [Test]
        public async Task A_certificate_revoked_after_publication_is_no_longer_served()
        {

            var chain     = ChainFor();

            var added     = await Manufacturer().AddOEMProvCert(chain);
            var before    = await Operator().GetOEMProvCert(pcid);

            oemResponder.Revoke(chain.VehicleCertificate, RevocationReason.CessationOfOperation);
            revoked.Add(chain.VehicleCertificate);

            var after     = await Operator().GetOEMProvCert(pcid);

            Assert.Multiple(() => {
                Assert.That(added.IsSuccess,   Is.True,  added.Error?.ToString());
                Assert.That(before.IsSuccess,  Is.True,  before.Error?.ToString());
                Assert.That(after.IsSuccess,   Is.False, "Revoked between the two reads.");
                Assert.That(after.Error!.FirstMessage,  Does.Contain("revoked"));
            });

        }

        #endregion

        #region A_certificate_whose_name_is_not_a_PCID_is_refused()

        [Test]
        public async Task A_certificate_whose_name_is_not_a_PCID_is_refused()
        {

            var notAVehicle = pki.IssueProvisioningCertificate(PCID.Parse("ECD00000000000000"));

            // A certificate for something that is not a vehicle at all.
            var chain       = new ProvisioningCertificate(
                                  pki.IssueSECCCertificate("DE*ICE*E45B*78C").Certificate,
                                  pki.OEMSubCA1.Certificate,
                                  pki.OEMSubCA2.Certificate
                              );

            var response    = await Manufacturer().AddOEMProvCert(chain);

            Assert.Multiple(() => {
                Assert.That(notAVehicle.Certificate.CommonName,  Is.EqualTo("ECD00000000000000"), "Precondition.");
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("pcid : must match"));
            });

        }

        #endregion

        #region Nonsense_in_place_of_a_certificate_is_refused()

        [Test]
        public async Task Nonsense_in_place_of_a_certificate_is_refused()
        {

            var response = await new RawOPCPClient(baseURL, TokenFor([ OPCPRole.OEM ], [ ecd ])).
                                     SendRaw(HTTPMethod.PUT,
                                             "/v1/oem/provCerts",
                                             new Newtonsoft.Json.Linq.JObject(
                                                 new Newtonsoft.Json.Linq.JProperty("vehicleCertificate",  "SGVsbG8gV29ybGQh"),
                                                 new Newtonsoft.Json.Linq.JProperty("subCA1Certificate",   "SGVsbG8gV29ybGQh")
                                             ));

            Assert.Multiple(() => {
                Assert.That(response.HTTPStatusCode,        Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(response.HTTPBodyAsUTF8String,  Does.Contain("Invalid certificate format on vehicleCertificate"));
            });

        }

        #endregion


        #region A_manufacturer_may_only_publish_its_own_vehicles()

        /// <summary>
        /// Step one of the validation, and the reason the World Manufacturer Identifier is in the
        /// token at all: it keeps one manufacturer out of another's vehicles.
        /// </summary>
        [Test]
        public async Task A_manufacturer_may_only_publish_its_own_vehicles()
        {

            var otherMaker = NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("XYZ") ]);

            var response   = await otherMaker.AddOEMProvCert(ChainFor());

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,            Is.False);
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("ECD"));
            });

        }

        #endregion

        #region A_manufacturer_may_only_depublish_its_own_vehicles()

        [Test]
        public async Task A_manufacturer_may_only_depublish_its_own_vehicles()
        {

            await Manufacturer().AddOEMProvCert(ChainFor());

            var otherMaker = NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("XYZ") ]);
            var response   = await otherMaker.DeleteOEMProvCert(pcid);
            var stillThere = await pcpAPI.Store.Contains(pcid);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,       Is.False);
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(stillThere,               Is.True, "And it is still there.");
            });

        }

        #endregion

        #region An_operator_may_read_but_not_publish()

        [Test]
        public async Task An_operator_may_read_but_not_publish()
        {

            await Manufacturer().AddOEMProvCert(ChainFor());

            var operatorClient = Operator();

            var read    = await operatorClient.GetOEMProvCert(pcid);
            var written = await operatorClient.AddOEMProvCert(ChainFor(PCID.Parse("ECD99999999999999")));
            var deleted = await operatorClient.DeleteOEMProvCert(pcid);

            Assert.Multiple(() => {
                Assert.That(read.IsSuccess,           Is.True, read.Error?.ToString());
                Assert.That(written.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(deleted.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region A_charge_point_operator_has_no_business_here()

        /// <summary>
        /// The roles table gives the charge point operator no access to this pool at all - it
        /// never needs a vehicle's provisioning certificate.
        /// </summary>
        [Test]
        public async Task A_charge_point_operator_has_no_business_here()
        {

            await Manufacturer().AddOEMProvCert(ChainFor());

            var response = await NewPCPClient([ OPCPRole.CPO ]).GetOEMProvCert(pcid);

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));

        }

        #endregion


        #region Republishing_the_same_vehicle_replaces_what_was_there()

        [Test]
        public async Task Republishing_the_same_vehicle_replaces_what_was_there()
        {

            var manufacturer  = Manufacturer();

            var first         = ChainFor();
            var second        = ChainFor();   // a new certificate, and a new key with it

            await manufacturer.AddOEMProvCert(first);
            await manufacturer.AddOEMProvCert(second);

            var fetched       = await Operator().GetOEMProvCert(pcid);

            Assert.Multiple(() => {
                Assert.That(fetched.Data!.VehicleCertificate,  Is.EqualTo(second.VehicleCertificate));
                Assert.That(fetched.Data!.VehicleCertificate,  Is.Not.EqualTo(first.VehicleCertificate));
                Assert.That(pcpAPI.Store.GetAll().Result,      Has.Exactly(1).Items, "One vehicle, not two.");
            });

        }

        #endregion

        #region A_new_key_pair_raises_the_workshop_case()

        /// <summary>
        /// Republishing a vehicle with a different key pair makes every contract written against
        /// the old key worthless. The pool says so, and in phase 5 the contract certificate pool
        /// will be listening.
        /// </summary>
        [Test]
        public async Task A_new_key_pair_raises_the_workshop_case()
        {

            var manufacturer  = Manufacturer();
            var raised        = new List<PCID>();

            Task OnKeyChanged(PCID pcid, ProvisioningCertificate certificate)
            {
                raised.Add(pcid);
                return Task.CompletedTask;
            }

            pcpAPI.OnVehicleKeyChanged += OnKeyChanged;

            try
            {

                await manufacturer.AddOEMProvCert(ChainFor());
                Assert.That(raised, Is.Empty, "The first publication replaces nothing.");

                await manufacturer.AddOEMProvCert(ChainFor());

                Assert.That(raised,  Is.EqualTo(new[] { pcid }), "The second carries a new key.");

            }
            finally
            {
                pcpAPI.OnVehicleKeyChanged -= OnKeyChanged;
            }

        }

        #endregion

        #region Depublishing_a_vehicle_announces_it()

        /// <summary>
        /// A delete reaches further than this pool: the contract certificate pool has to delete
        /// every contract belonging to the vehicle, and revoke the ones an operator-owned
        /// authority issued.
        /// </summary>
        [Test]
        public async Task Depublishing_a_vehicle_announces_it()
        {

            var manufacturer  = Manufacturer();
            var announced     = new List<PCID>();

            Task OnDeleted(PCID pcid, ProvisioningCertificate certificate)
            {
                announced.Add(pcid);
                return Task.CompletedTask;
            }

            pcpAPI.OnProvisioningCertificateDeleted += OnDeleted;

            try
            {

                await manufacturer.AddOEMProvCert(ChainFor());

                var deleted = await manufacturer.DeleteOEMProvCert(pcid);
                var again   = await manufacturer.DeleteOEMProvCert(pcid);
                var lookup  = await manufacturer.LookupVehicle(pcid);

                Assert.Multiple(() => {
                    Assert.That(deleted.IsSuccess,       Is.True, deleted.Error?.ToString());
                    Assert.That(announced,               Is.EqualTo(new[] { pcid }));
                    Assert.That(again.HTTPStatusCode,    Is.EqualTo(HTTPStatusCode.NotFound), "Only once.");
                    Assert.That(lookup.HTTPStatusCode,   Is.EqualTo(HTTPStatusCode.NotFound));
                });

            }
            finally
            {
                pcpAPI.OnProvisioningCertificateDeleted -= OnDeleted;
            }

        }

        #endregion

        #region An_unknown_vehicle_is_a_404()

        [Test]
        public async Task An_unknown_vehicle_is_a_404()
        {

            var response = await Operator().GetOEMProvCert(PCID.Parse("ECD00000000000001"));

            Assert.Multiple(() => {
                Assert.That(response.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(response.Error!.FirstMessage,  Does.Contain("not found"));
                Assert.That(response.TraceId,              Is.Not.Null);
            });

        }

        #endregion

        #region The_renamed_property_spellings_are_both_read()

        /// <summary>
        /// The specification announces that subCA1Certificate becomes subCa1Certificate and
        /// vehicleCertificate becomes provisioningCertificate. A pool that understood only one
        /// spelling would break on whichever day that lands.
        /// </summary>
        [Test]
        public void The_renamed_property_spellings_are_both_read()
        {

            var chain    = ChainFor();
            var current  = chain.ToJSON();

            var future   = new Newtonsoft.Json.Linq.JObject(
                               new Newtonsoft.Json.Linq.JProperty("provisioningCertificate",  chain.VehicleCertificate.Base64),
                               new Newtonsoft.Json.Linq.JProperty("subCa1Certificate",        chain.SubCA1Certificate. Base64),
                               new Newtonsoft.Json.Linq.JProperty("subCa2Certificate",        chain.SubCA2Certificate!.Base64)
                           );

            Assert.Multiple(() => {

                Assert.That(ProvisioningCertificate.TryParse(current, out var fromCurrent, out var currentError),  Is.True, currentError);
                Assert.That(ProvisioningCertificate.TryParse(future,  out var fromFuture,  out var futureError),   Is.True, futureError);

                Assert.That(fromCurrent!.VehicleCertificate,  Is.EqualTo(chain.VehicleCertificate));
                Assert.That(fromFuture!. VehicleCertificate,  Is.EqualTo(chain.VehicleCertificate));
                Assert.That(fromFuture.  SubCA2Certificate,   Is.EqualTo(chain.SubCA2Certificate));

                // The current spelling is what goes back out.
                Assert.That(current["vehicleCertificate"],  Is.Not.Null);
                Assert.That(current["subCA1Certificate"],   Is.Not.Null);

            });

        }

        #endregion

    }

}
