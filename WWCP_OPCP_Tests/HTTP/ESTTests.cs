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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.opcp.Tests.Infrastructure;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// The enrollment interface of the V2G PKI: where every certificate in the ecosystem comes
    /// from, and the one place that decides what a certificate is allowed to claim to be.
    /// </summary>
    [TestFixture]
    public class ESTTests : AOPCPEcosystemTests
    {

        #region Data

        private static readonly PCID     pcid    = PCID.   Parse("ECD12345671234567");
        private static readonly EMA_Id   emaId   = EMA_Id. Parse("DEECD123456789");
        private static readonly EVSE_Id  evseId  = EVSE_Id.Parse("DE*ICE*E45B*78C");
        private static readonly SECC_Id  seccId  = SECC_Id.Parse("DE-ICE-S-00003C4D557878675645330967543476-2");

        private static readonly CA_Id    cpo     = CA_Id.Parse(CA_Type.CPO);
        private static readonly CA_Id    mo      = CA_Id.Parse(CA_Type.MO);
        private static readonly CA_Id    oem     = CA_Id.Parse(CA_Type.OEM);
        private static readonly CA_Id    veh     = CA_Id.Parse(CA_Type.VEH);
        private static readonly CA_Id    cps     = CA_Id.Parse(CA_Type.CPS);


        private EST_HTTPClient ChargePointOperator()
            => new (baseURL, TokenFor(OPCPRole.CPO));

        private EST_HTTPClient Manufacturer()
            => new (baseURL, TokenFor([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]));

        private EST_HTTPClient MobilityOperator()
            => new (baseURL, TokenFor([ OPCPRole.MO_V2GPKI ], null, [ emaId.ProviderId ]));

        private EST_HTTPClient ProvisioningService()
            => new (baseURL, TokenFor(OPCPRole.CPS));


        /// <summary>
        /// A key pair and the request that asks for a certificate on it.
        /// </summary>
        private static (AsymmetricCipherKeyPair KeyPair, Pkcs10CertificationRequest CSR) Ask(String CommonName)
        {

            var keyPair = PKIFactory.GenerateECCKeyPair("secp256r1");

            return (keyPair,
                    CSRBuilder.Create(CommonName, keyPair, "GraphDefined GmbH", "DE"));

        }

        #endregion


        #region A_charging_station_gets_the_certificate_it_authenticates_with()

        /// <summary>
        /// What a vehicle checks during the TLS handshake before it will talk ISO 15118 at all.
        /// </summary>
        [Test]
        public async Task A_charging_station_gets_the_certificate_it_authenticates_with()
        {

            var (_, csr)  = Ask(evseId.ToString());

            var enrolled  = await ChargePointOperator().SimpleEnroll(cpo, csr);

            Assert.That(enrolled.IsSuccess,  Is.True, enrolled.Error?.ToString());

            var chain     = enrolled.Data!.ToArray();
            var leaf      = chain[0];

            Assert.Multiple(() => {

                Assert.That(leaf.CommonName,  Is.EqualTo(evseId.ToString()));

                // Issued by the charge point operator authority, and verifiable from the V2G root
                // a vehicle carries.
                Assert.That(PnCChainValidator.Validate(leaf,
                                                       chain.Skip(1),
                                                       [ pki.V2GRoot.Certificate ],
                                                       ExpectedCommonName: evseId.ToString()).IsValid,
                            Is.True);

            });

        }

        #endregion

        #region A_manufacturer_enrolls_a_vehicle_and_publishes_it()

        /// <summary>
        /// The beginning of the whole story, end to end: a manufacturer asks the V2G PKI for the
        /// certificate a car is born with, and puts the answer straight into the provisioning
        /// certificate pool - which accepts it, because it validates exactly the same way.
        /// </summary>
        [Test]
        public async Task A_manufacturer_enrolls_a_vehicle_and_publishes_it()
        {

            await SeedRootCertificates();

            var (_, csr)   = Ask(pcid.ToString());

            var enrolled   = await Manufacturer().SimpleEnroll(oem, csr);

            Assert.That(enrolled.IsSuccess,  Is.True, enrolled.Error?.ToString());

            var chain      = enrolled.Data!.ToArray();

            var published  = await NewPCPClient([ OPCPRole.OEM ], [ WMI.Parse("ECD") ]).AddOEMProvCert(
                                       new ProvisioningCertificate(chain[0],
                                                                   chain[2],
                                                                   chain[1])
                                   );

            Assert.Multiple(() => {
                Assert.That(chain[0].CommonName,  Is.EqualTo(pcid.ToString()));
                Assert.That(published.IsSuccess,  Is.True, published.Error?.ToString());
            });

            await pcpAPI.Store.Remove(pcid);

        }

        #endregion

        #region A_mobility_operator_and_a_provisioning_service_enroll_theirs()

        /// <summary>
        /// The other two leaves of the V2G PKI: a contract certificate and the certificate a
        /// provisioning service signs contract data with.
        /// </summary>
        [Test]
        public async Task A_mobility_operator_and_a_provisioning_service_enroll_theirs()
        {

            var (_, contractCSR)  = Ask(emaId.ToString());
            var (_, signerCSR)    = Ask("CPS Provisioning Signer 2026.1");

            var contract          = await MobilityOperator().   SimpleEnroll(mo,  contractCSR);
            var signer            = await ProvisioningService().SimpleEnroll(cps, signerCSR);

            Assert.That(contract.IsSuccess,  Is.True, contract.Error?.ToString());
            Assert.That(signer.  IsSuccess,  Is.True, signer.  Error?.ToString());

            Assert.Multiple(() => {

                Assert.That(contract.Data!.First().CommonName,  Is.EqualTo(emaId.ToString()));
                Assert.That(signer.  Data!.First().CommonName,  Is.EqualTo("CPS Provisioning Signer 2026.1"));

                // The provisioning signing authority is the one with no common name rule at all:
                // its certificates identify a service rather than a thing in ISO 15118.
                Assert.That(signer.Data!.Skip(1).First().CommonName,
                            Is.EqualTo(pki.CPSSubCA2.Certificate.CommonName));

            });

        }

        #endregion

        #region What_comes_back_is_the_leaf_and_the_authorities_but_not_the_root()

        /// <summary>
        /// The same rule as everywhere else in OPCP: the trust anchor does not travel. A
        /// recipient is supposed to have its roots from the root certificate pool, and a root
        /// that arrived alongside the thing it vouches for would vouch for nothing.
        /// </summary>
        [Test]
        public async Task What_comes_back_is_the_leaf_and_the_authorities_but_not_the_root()
        {

            var (_, csr)  = Ask(evseId.ToString());

            var enrolled  = await ChargePointOperator().SimpleEnroll(cpo, csr);

            Assert.That(enrolled.IsSuccess,  Is.True, enrolled.Error?.ToString());

            var chain     = enrolled.Data!.ToArray();

            Assert.Multiple(() => {

                Assert.That(chain,                Has.Exactly(3).Items);
                Assert.That(chain[1].CommonName,  Is.EqualTo(pki.CPOSubCA2.Certificate.CommonName));
                Assert.That(chain[2].CommonName,  Is.EqualTo(pki.CPOSubCA1.Certificate.CommonName));

                Assert.That(chain.Any(certificate => certificate.SHA256Fingerprint == pki.V2GRoot.Certificate.SHA256Fingerprint),
                            Is.False,
                            "The root is not part of what enrollment hands back.");

            });

        }

        #endregion


        #region The_common_name_has_to_be_what_the_authority_certifies()

        /// <summary>
        /// The check the whole ecosystem downstream depends on. Nothing in a certificate says
        /// what it is for except its common name, so an authority that certified the wrong shape
        /// of name would put something into the world that everything else would misread.
        /// </summary>
        [Test]
        public async Task The_common_name_has_to_be_what_the_authority_certifies()
        {

            var (_, vehicleName)  = Ask(pcid.  ToString());
            var (_, stationName)  = Ask(evseId.ToString());
            var (_, nonsense)     = Ask("not an ISO 15118 identifier");

            var stationFromOEM    = await Manufacturer().      SimpleEnroll(oem, stationName);
            var vehicleFromCPO    = await ChargePointOperator().SimpleEnroll(cpo, vehicleName);
            var contractFromMO    = await MobilityOperator().  SimpleEnroll(mo,  nonsense);

            Assert.Multiple(() => {
                Assert.That(stationFromOEM.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(vehicleFromCPO.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
                Assert.That(contractFromMO.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));
            });

        }

        #endregion

        #region A_charging_station_may_also_be_named_the_way_ISO_15118_20_names_one()

        /// <summary>
        /// ISO 15118-20 identifies the communication controller rather than a power outlet, so
        /// the charge point operator authority takes a SECCID where the earlier generation has an
        /// EVSEID.
        /// </summary>
        [Test]
        public async Task A_charging_station_may_also_be_named_the_way_ISO_15118_20_names_one()
        {

            var (_, csr)  = Ask(seccId.ToString());

            var enrolled  = await ChargePointOperator().SimpleEnroll(cpo, csr, XSD_MsgDefNamespace.ISO15118_20);

            Assert.That(enrolled.IsSuccess,  Is.True, enrolled.Error?.ToString());
            Assert.That(enrolled.Data!.First().CommonName,  Is.EqualTo(seccId.ToString()));

        }

        #endregion

        #region A_manufacturer_may_only_enroll_its_own_vehicles()

        /// <summary>
        /// The World Manufacturer Identifier a PCID begins with decides whose vehicle it is, here
        /// exactly as in the provisioning certificate pool. A well-formed name belonging to
        /// somebody else is a refusal of a different kind than a malformed one.
        /// </summary>
        [Test]
        public async Task A_manufacturer_may_only_enroll_its_own_vehicles()
        {

            var (_, csr)  = Ask("XYZ98765439876543");

            var enrolled  = await Manufacturer().SimpleEnroll(oem, csr);

            Assert.Multiple(() => {
                Assert.That(enrolled.IsSuccess,       Is.False);
                Assert.That(enrolled.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region An_authority_is_only_open_to_the_role_it_belongs_to()

        /// <summary>
        /// From the rights matrix rather than from the interface document, which lists the four
        /// roles once for the whole operation and so cannot say that a charge point operator has
        /// no business at the vehicle manufacturers' authority.
        /// </summary>
        [Test]
        public async Task An_authority_is_only_open_to_the_role_it_belongs_to()
        {

            var (_, vehicleName)  = Ask(pcid.ToString());
            var (_, stationName)  = Ask(evseId.ToString());

            var vehicleAsCPO      = await ChargePointOperator().SimpleEnroll(veh, vehicleName);
            var stationAsOEM      = await Manufacturer().       SimpleEnroll(cpo, stationName);

            Assert.Multiple(() => {
                Assert.That(vehicleAsCPO.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
                Assert.That(stationAsOEM.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden));
            });

        }

        #endregion

        #region Enrolling_without_a_token_gets_nowhere()

        /// <summary>
        /// Unlike the revocation responders beside it, the enrollment service is authenticated -
        /// it hands out certificates.
        /// </summary>
        [Test]
        public async Task Enrolling_without_a_token_gets_nowhere()
        {

            var (_, csr)  = Ask(evseId.ToString());

            var enrolled  = await new EST_HTTPClient(baseURL).SimpleEnroll(cpo, csr);

            Assert.That(enrolled.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized));

        }

        #endregion


        #region A_request_written_for_a_file_is_read_as_well_as_one_written_for_a_wire()

        /// <summary>
        /// The interface takes base64, and a client that has a request in a file has it with a
        /// header, a footer and line breaks. Both are read.
        /// </summary>
        [Test]
        public async Task A_request_written_for_a_file_is_read_as_well_as_one_written_for_a_wire()
        {

            var (_, csr)  = Ask(evseId.ToString());

            var armoured  = "-----BEGIN CERTIFICATE REQUEST-----\r\n" +
                            String.Join("\r\n", Chunks(csr.ToBase64(), 64)) +
                            "\r\n-----END CERTIFICATE REQUEST-----\r\n";

            var response  = await Raw(OPCPRole.CPO).SendRawBytes(
                                      HTTPMethod.POST,
                                      $"{EST_HTTPClient.URLPrefix}/{cpo}/simpleenroll/ISO15118-2",
                                      Encoding.ASCII.GetBytes(armoured),
                                      OPCPContentTypes.PKCS10
                                  );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));

        }

        #endregion

        #region A_request_that_is_not_a_request_is_refused()

        /// <summary>
        /// And refused as a bad request rather than as a server error, because it is one.
        /// </summary>
        [Test]
        public async Task A_request_that_is_not_a_request_is_refused()
        {

            var response = await Raw(OPCPRole.CPO).SendRawBytes(
                                     HTTPMethod.POST,
                                     $"{EST_HTTPClient.URLPrefix}/{cpo}/simpleenroll/ISO15118-2",
                                     Encoding.ASCII.GetBytes("bm90IGEgY2VydGlmaWNhdGUgc2lnbmluZyByZXF1ZXN0"),
                                     OPCPContentTypes.PKCS10
                                 );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadRequest));

        }

        #endregion

        #region The_answer_is_a_certificates_only_PKCS7_and_says_so()

        /// <summary>
        /// RFC 7030 §4.1.3 names the media type and puts the encoding in a header of its own.
        /// A client that is not this library reads both.
        /// </summary>
        [Test]
        public async Task The_answer_is_a_certificates_only_PKCS7_and_says_so()
        {

            var response = await Raw(OPCPRole.CPO).SendRaw(
                                     HTTPMethod.GET,
                                     $"/{cpo}/cacerts/ISO15118-2/secp256r1/"
                                 );

            Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));

            Assert.Multiple(() => {

                Assert.That(response.GetHeaderField("Content-Type"),
                            Is.EqualTo("application/pkcs7-mime; smime-type=certs-only"));

                Assert.That(response.GetHeaderField("Content-Transfer-Encoding"),
                            Is.EqualTo("base64"));

            });

        }

        #endregion


        #region CA_distribution_hands_over_the_whole_path_root_included()

        /// <summary>
        /// The one operation whose point <em>is</em> to hand over a trust anchor, which is why
        /// this one carries the root that enrollment leaves out.
        /// </summary>
        [Test]
        public async Task CA_distribution_hands_over_the_whole_path_root_included()
        {

            var chain = await ChargePointOperator().CACerts(cpo, SignatureAlgorithm.secp256r1);

            Assert.That(chain.IsSuccess,  Is.True, chain.Error?.ToString());

            var certificates = chain.Data!.ToArray();

            Assert.Multiple(() => {

                Assert.That(certificates,                Has.Exactly(3).Items);
                Assert.That(certificates[0].CommonName,  Is.EqualTo(pki.CPOSubCA2.Certificate.CommonName));
                Assert.That(certificates[1].CommonName,  Is.EqualTo(pki.CPOSubCA1.Certificate.CommonName));
                Assert.That(certificates[2].SHA256Fingerprint,
                            Is.EqualTo(pki.V2GRoot.Certificate.SHA256Fingerprint));

            });

        }

        #endregion

        #region CA_distribution_is_served_where_the_document_puts_it_and_where_RFC_7030_does()

        /// <summary>
        /// The interface document puts this one at the root with no prefix at all, where RFC 7030
        /// - which the same document calls itself fully compliant with - puts it under
        /// /.well-known/est. Both are served, because a caller following either is following
        /// something that was written down.
        /// </summary>
        [Test]
        public async Task CA_distribution_is_served_where_the_document_puts_it_and_where_RFC_7030_does()
        {

            var raw          = Raw(OPCPRole.CPO);

            var asDocumented = await raw.SendRaw(HTTPMethod.GET, $"/{cpo}/cacerts/ISO15118-2/secp256r1/");
            var asInTheRFC   = await raw.SendRaw(HTTPMethod.GET, $"{EST_HTTPClient.URLPrefix}/{cpo}/cacerts/ISO15118-2/secp256r1");

            Assert.Multiple(() => {
                Assert.That(asDocumented.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));
                Assert.That(asInTheRFC.  HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.OK));
            });

            Assert.That(Encoding.ASCII.GetString(asInTheRFC.HTTPBody ?? []),
                        Is.EqualTo(Encoding.ASCII.GetString(asDocumented.HTTPBody ?? [])),
                        "The same authority, whichever path it was asked for through.");

        }

        #endregion

        #region A_hierarchy_this_service_does_not_operate_is_not_invented()

        /// <summary>
        /// A V2G PKI runs its hierarchy once per curve, because a vehicle that only speaks
        /// secp256r1 cannot verify a chain signed on ed448. Asking for one that is not there gets
        /// a plain no.
        /// </summary>
        [Test]
        public async Task A_hierarchy_this_service_does_not_operate_is_not_invented()
        {

            var onEd448      = await ChargePointOperator().CACerts(cpo, SignatureAlgorithm.ed448);

            var fromNobody   = await ChargePointOperator().CACerts(CA_Id.Parse("acme-cpo"),
                                                                   SignatureAlgorithm.secp256r1);

            Assert.Multiple(() => {
                Assert.That(onEd448.   HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(fromNobody.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
            });

        }

        #endregion


        #region (helpers)

        private RawOPCPClient Raw(params OPCPRole[] Roles)
            => new (baseURL, TokenFor(Roles));

        private static IEnumerable<String> Chunks(String Text, Int32 Size)
        {
            for (var i = 0; i < Text.Length; i += Size)
                yield return Text.Substring(i, Math.Min(Size, Text.Length - i));
        }

        #endregion

    }

}
