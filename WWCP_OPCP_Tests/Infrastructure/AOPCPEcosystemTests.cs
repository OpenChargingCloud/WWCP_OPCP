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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.Infrastructure
{

    /// <summary>
    /// A whole Plug&amp;Charge ecosystem, in this process.
    ///
    /// An HTTP server on a port the operating system picks, the OPCP services on top of it, and a
    /// token issuer standing in for the identity provider a real deployment would have. Clients
    /// talk to it over a real socket, so what the tests exercise is the protocol rather than a
    /// method call dressed up as one.
    /// </summary>
    public abstract class AOPCPEcosystemTests
    {

        #region Data

        /// <summary>The server everything is mounted on.</summary>
        protected HTTPServer       httpServer    = null!;

        /// <summary>The Root Certificate Pool.</summary>
        protected RCP_HTTPAPI      rcpAPI        = null!;

        /// <summary>Stands in for the ecosystem's identity provider.</summary>
        protected TestTokenIssuer  tokenIssuer   = null!;

        /// <summary>The OAuth2 token endpoint.</summary>
        protected AccessToken_HTTPAPI  tokenAPI  = null!;

        /// <summary>Where the ecosystem lives.</summary>
        protected URL              baseURL;

        /// <summary>How a client addresses this ecosystem.</summary>
        protected OPCPEndpointConfig  endpointConfig = null!;

        /// <summary>The ecosystem's three certificate hierarchies.</summary>
        protected PnCTestPKI       pki           = null!;

        /// <summary>Answers for the certificates the vehicle manufacturers' issuing CA signed.</summary>
        protected OCSPResponder    oemResponder  = null!;

        /// <summary>Where each issuing authority's responder answers, by that authority's fingerprint.</summary>
        private readonly Dictionary<String, URL> responderURLs = [];

        /// <summary>Where the responder answers.</summary>
        protected URL              ocspURL;

        /// <summary>The Provisioning Certificate Pool.</summary>
        protected PCP_HTTPAPI      pcpAPI        = null!;

        /// <summary>The Contract Certificate Pool.</summary>
        protected CCP_HTTPAPI      ccpAPI        = null!;

        /// <summary>The Certificate Provisioning Service.</summary>
        protected CPS_HTTPAPI      cpsAPI        = null!;

        /// <summary>The V2G PKI's enrollment service.</summary>
        protected EST_HTTPAPI      estAPI        = null!;

        /// <summary>The certificate the contract provisioning service signs with.</summary>
        protected IssuedCertificate  cpsSigner   = null!;

        #endregion

        #region Setup / teardown

        /// <summary>
        /// Start the ecosystem once for the whole fixture.
        /// </summary>
        [OneTimeSetUp]
        public async Task StartEcosystem()
        {

            // Port zero: the operating system picks a free one, so two fixtures running at
            // once never collide and no developer's machine has to have a port free.
            httpServer   = await HTTPServer.StartNew();

            baseURL         = URL.Parse($"http://127.0.0.1:{httpServer.TCPPort}");

            endpointConfig  = new OPCPEndpointConfig(baseURL);

            tokenIssuer     = new TestTokenIssuer(baseURL);

            tokenAPI        = new AccessToken_HTTPAPI(
                                  httpServer,
                                  tokenIssuer
                              );

            rcpAPI          = new RCP_HTTPAPI(
                                  httpServer,
                                  AccessTokenValidator: tokenIssuer
                              );

            // One infrastructure for the whole fixture: building it means generating fourteen
            // key pairs, which is cheap once and wasteful per test.
            pki             = new PnCTestPKI();

            // A responder per issuing authority, as a real PKI has: each answers only for the
            // certificates it signed, and an asker verifies the answer against that authority.
            // A single responder for a whole hierarchy cannot work - its signature would be
            // wrong for every level but one.
            oemResponder    = MountResponder("oem-sub2", pki.OEMSubCA2);
                              MountResponder("oem-sub1", pki.OEMSubCA1);
                              MountResponder("oem-root", pki.OEMRoot);

            ocspURL         = responderURLs[pki.OEMSubCA2.Certificate.SHA256Fingerprint];

            pcpAPI          = new PCP_HTTPAPI(
                                  httpServer,
                                  rcpAPI.Store,
                                  AccessTokenValidator:  tokenIssuer,
                                  RevocationCheck:       CheckRevocation
                              );

            ccpAPI          = new CCP_HTTPAPI(
                                  httpServer,
                                  AccessTokenValidator: tokenIssuer
                              );

            // The contract pool follows what happens to vehicles: a car whose provisioning
            // certificate is gone, or whose key changed, cannot use its contracts any more.
            ccpAPI.AttachTo(pcpAPI);

            cpsSigner       = pki.IssueCPSSigningCertificate();

            // The service that signs contracts reaches all three pools: it reads vehicles from
            // one, checks the operator's chain against the anchors in another, and files what it
            // signed in the third. In one process those are the stores themselves; apart, they
            // would be clients behind the same interfaces.
            cpsAPI          = new CPS_HTTPAPI(
                                  httpServer,
                                  new InMemoryCpsSignerStore(cpsSigner),
                                  ContractCertificatePool:    ccpAPI.Store,
                                  Vehicles:                   pcpAPI.Store,
                                  ContractCertificateIssuer:  CPS_HTTPAPI.IssuedBy(pki.V2GMOSubCA2),
                                  RootCertificates:           rcpAPI.Store,
                                  AccessTokenValidator:       tokenIssuer
                              );

            #region The V2G PKI's enrollment service

            var authorities = new InMemoryCertificateAuthorityStore();

            await authorities.Add(CA_Id.Parse(CA_Type.CPO), pki.CPOSubCA2);
            await authorities.Add(CA_Id.Parse(CA_Type.MO),  pki.V2GMOSubCA2);
            await authorities.Add(CA_Id.Parse(CA_Type.CPS), pki.CPSSubCA2);
            await authorities.Add(CA_Id.Parse(CA_Type.OEM), pki.OEMSubCA2);

            // A real V2G PKI has a vehicle authority of its own below the V2G root, for the
            // certificates ISO 15118-20 asks for. This infrastructure has one manufacturer
            // authority and serves both from it, which is enough to exercise everything the
            // enrollment service decides - the two ask for the same kind of common name.
            await authorities.Add(CA_Id.Parse(CA_Type.VEH), pki.OEMSubCA2);

            estAPI          = new EST_HTTPAPI(
                                  httpServer,
                                  authorities,
                                  AccessTokenValidator: tokenIssuer
                              );

            #endregion

        }

        /// <summary>
        /// Ask the responder of the authority that issued the certificate.
        /// </summary>
        private Task<OCSPResult> CheckRevocation(PnCCertificate     Certificate,
                                                 PnCCertificate     Issuer,
                                                 CancellationToken  CancellationToken)

            => responderURLs.TryGetValue(Issuer.SHA256Fingerprint, out var url)

                   ? new OCSPClient(url).CheckStatus(Certificate,
                                                     Issuer,
                                                     CancellationToken: CancellationToken)

                   // Not knowing is not the same as good.
                   : Task.FromResult(OCSPResult.Unknown($"No responder is known for '{Issuer.CommonName}'."));

        /// <summary>
        /// Serve one authority's responder at its own path.
        /// </summary>
        private OCSPResponder MountResponder(String             Path,
                                             IssuedCertificate  Authority)
        {

            var responder = new OCSPResponder(Authority);

            new OCSP_HTTPAPI(
                httpServer,
                responder,
                HTTPPath.Parse($"/ocsp/{Path}/")
            );

            responderURLs[Authority.Certificate.SHA256Fingerprint] = URL.Parse($"{baseURL}/ocsp/{Path}/");

            return responder;

        }

        /// <summary>
        /// Empty the pools before each test, so that no test depends on what another left behind.
        /// </summary>
        [SetUp]
        public async Task ResetEcosystem()
        {

            foreach (var rootCertificate in await rcpAPI.Store.GetAll())
                if (rootCertificate.Id.HasValue)
                    await rcpAPI.Store.Remove(rootCertificate.Id.Value);

            foreach (var pcid in await pcpAPI.Store.GetAll())
            {
                await ccpAPI.Store.RemoveByVehicle(pcid);
                await pcpAPI.Store.Remove(pcid);
            }

            foreach (var emaId in contractsIssued)
                await ccpAPI.Store.Remove(emaId);

            contractsIssued.Clear();

        }

        private readonly List<EMA_Id> contractsIssued = [];

        #endregion

        #region NewContract(EMAId, PCID, OwnPKI = false)

        /// <summary>
        /// Mint a contract for a vehicle, exactly as a contract provisioning service would: a
        /// contract certificate, its private key wrapped so that only this vehicle can unwrap it,
        /// and the whole thing signed by the provisioning service.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="Vehicle">The vehicle's own certificate and key.</param>
        /// <param name="OwnPKI">Whether the operator brings its own PKI.</param>
        protected SignedContractData NewContract(EMA_Id             EMAId,
                                                 IssuedCertificate  Vehicle,
                                                 Boolean            OwnPKI   = false)
        {

            var contract  = pki.IssueContractCertificate(EMAId, OwnPKI);

            var wrapped   = ContractKeyCrypto.Wrap(contract.PrivateKey,
                                                   Vehicle.Certificate);

            var subCAs    = contract.SubCAs.ToArray();

            var data      = new ContractData(
                                contract.Certificate,
                                subCAs[^1],
                                wrapped.EncryptedPrivateKey,
                                wrapped.DHPublicKey,
                                subCAs.Length > 1 ? subCAs[0] : null,
                                EMAId
                            );

            var pcid      = PCID.Parse(Vehicle.Certificate.CommonName);

            var signed    = new SignedContractData(
                                EMAId,
                                pcid,
                                TestContractDataCodec.SignContractData(
                                    data,
                                    EMAId,
                                    pcid,
                                    cpsSigner.Certificate,
                                    cpsSigner.PrivateKey
                                ),
                                XSD_MsgDefNamespace.ISO15118_2,
                                CpsV2GRootCertificateFingerprint: pki.V2GRoot.Certificate.SHA256Fingerprint
                            );

            contractsIssued.Add(EMAId);

            return signed;

        }

        /// <summary>
        /// Admit this infrastructure's three roots into the pool.
        ///
        /// Not done automatically, because the root certificate pool's own tests count what they
        /// put there. Anything validating a chain has to call this first - which is honest: a
        /// chain cannot be validated against trust anchors an ecosystem was never given.
        /// </summary>
        protected async Task SeedRootCertificates()
        {

            await rcpAPI.Store.Add(new RootCertificate(RootCertificateType.OEM, pki.OEMRoot.Certificate));
            await rcpAPI.Store.Add(new RootCertificate(RootCertificateType.V2G, pki.V2GRoot.Certificate));
            await rcpAPI.Store.Add(new RootCertificate(RootCertificateType.MO,  pki.MORoot. Certificate));

        }

        /// <summary>
        /// Shut the ecosystem down.
        /// </summary>
        [OneTimeTearDown]
        public async Task StopEcosystem()
        {
            if (httpServer is not null)
                await httpServer.Stop();
        }

        #endregion


        #region TokenFor    (Roles)

        /// <summary>
        /// A token provider carrying a freshly issued token for the given roles.
        /// </summary>
        /// <param name="Roles">The roles the holder acts in.</param>
        protected IAccessTokenProvider TokenFor(params OPCPRole[] Roles)

            => new StaticAccessTokenProvider(
                   tokenIssuer.IssueToken(Roles: Roles).AccessToken
               );

        /// <summary>
        /// A token provider scoped to particular vehicle manufacturers or e-mobility providers.
        /// </summary>
        /// <param name="Roles">The roles the holder acts in.</param>
        /// <param name="WMIs">The vehicle manufacturers it may act for.</param>
        /// <param name="ProviderIds">The e-mobility providers it may act for.</param>
        protected IAccessTokenProvider TokenFor(OPCPRole[]      Roles,
                                                WMI[]?          WMIs          = null,
                                                Provider_Id[]?  ProviderIds   = null)

            => new StaticAccessTokenProvider(
                   tokenIssuer.IssueToken(Roles, WMIs, ProviderIds).AccessToken
               );

        #endregion

        #region NewPCPClient(Roles, WMIs)

        /// <summary>
        /// A Provisioning Certificate Pool client acting in the given roles for the given
        /// vehicle manufacturers.
        /// </summary>
        /// <param name="Roles">The roles the client acts in.</param>
        /// <param name="WMIs">The manufacturers it may act for.</param>
        protected PCP_HTTPClient NewPCPClient(OPCPRole[]  Roles,
                                              WMI[]?      WMIs    = null)

            => new (baseURL,
                    Roles.Length != 0
                        ? TokenFor(Roles, WMIs)
                        : null);

        #endregion

        #region NewRCPClient(Roles)

        /// <summary>
        /// A Root Certificate Pool client acting in the given roles - or, with none given,
        /// one carrying no token at all.
        /// </summary>
        /// <param name="Roles">The roles the client acts in.</param>
        protected RCP_HTTPClient NewRCPClient(params OPCPRole[] Roles)

            => new (
                   baseURL,
                   Roles.Length != 0
                       ? TokenFor(Roles)
                       : null
               );

        #endregion

        #region (static) NewRootCA(CommonName, CurveName = "secp256r1")

        /// <summary>
        /// Mint a root CA certificate to admit into a pool.
        /// </summary>
        /// <param name="CommonName">The common name of the root.</param>
        /// <param name="CurveName">One of the three curves OPCP names, or "ed448".</param>
        protected static PnCCertificate NewRootCA(String  CommonName,
                                                  String  CurveName    = "secp256r1")

            => PnCCertificate.From(
                   PKIFactory.CreateRootCACertificate(
                       CommonName,
                       CurveName == "ed448"
                           ? PKIFactory.GenerateEd448KeyPair()
                           : PKIFactory.GenerateECCKeyPair(CurveName)
                   )
               );

        #endregion

    }

}
