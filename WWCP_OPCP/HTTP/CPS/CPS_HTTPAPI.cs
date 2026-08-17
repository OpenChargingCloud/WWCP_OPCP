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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Issue a contract certificate for a mobility operator that has no PKI of its own.
    /// </summary>
    /// <param name="EMAId">The contract. It becomes the certificate's common name.</param>
    /// <param name="ContractBegins">When the contract starts.</param>
    /// <param name="ContractEnds">When it ends.</param>
    /// <returns>The certificate and its key, or null when none could be issued.</returns>
    public delegate IssuedCertificate? ContractCertificateIssuerDelegate(EMA_Id          EMAId,
                                                                         DateTimeOffset  ContractBegins,
                                                                         DateTimeOffset  ContractEnds);


    /// <summary>
    /// A Certificate Provisioning Service: the only thing in the ecosystem whose signature a
    /// vehicle will accept on a contract.
    ///
    /// A mobility operator with a PKI of its own brings a contract it has already issued and asks
    /// for it to be signed. One without brings only the description of a contract, and the service
    /// has it issued under the V2G root as well. Either way what comes back is contract data a
    /// vehicle can verify, and - unless the operator wants to file it itself - it goes straight
    /// into the contract certificate pool.
    /// </summary>
    public class CPS_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the Certificate Provisioning Service is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath             = HTTPPath.Parse("/v1/cps/");

        /// <summary>
        /// Where the signer discovery is mounted - without the version prefix, because that is
        /// where the specification puts it.
        /// </summary>
        public static readonly HTTPPath DefaultSignerDiscoveryPath  = HTTPPath.Parse("/cps/");

        #endregion

        #region Properties

        /// <summary>
        /// The certificates this service signs with.
        /// </summary>
        public ICpsSignerStore                  Signers                      { get; }

        /// <summary>
        /// What produces the ISO 15118 structures this service signs.
        /// </summary>
        public IContractDataCodec               Codec                        { get; }

        /// <summary>
        /// Where signed contracts are filed.
        /// </summary>
        /// <remarks>
        /// The pool's own store, because in a single process that is what it is. A service running
        /// apart from its pool puts a client behind this interface instead; nothing above it
        /// changes.
        /// </remarks>
        public IContractDataStore?              ContractCertificatePool      { get; }

        /// <summary>
        /// Where the vehicles are, for the operations that need a car's public key in order to
        /// wrap a contract's private key for it.
        /// </summary>
        public IProvisioningCertificateStore?   Vehicles                     { get; }

        /// <summary>
        /// How a contract certificate is issued for an operator without a PKI of its own.
        ///
        /// Optional, and without it that one operation is refused: a service that operates no
        /// mobility operator authority has nothing to issue with.
        /// </summary>
        public ContractCertificateIssuerDelegate?  ContractCertificateIssuer { get; }

        /// <summary>
        /// Where the trust anchors come from, when contract data is to be checked before it is
        /// signed.
        /// </summary>
        /// <remarks>
        /// Optional, and when it is absent an operator's own chain is signed as given. That is a
        /// deliberate escape hatch for a development ecosystem, and a hole anywhere else: a
        /// signature from this service is the whole reason the pool - and eventually a vehicle -
        /// accepts a contract.
        /// </remarks>
        public IRootCertificateStore?           RootCertificates             { get; }

        /// <summary>
        /// The second, un-prefixed mount that serves the signer discovery.
        /// </summary>
        public CpsSignerDiscovery_HTTPAPI       SignerDiscovery              { get; }

        #endregion

        #region Events

        /// <summary>
        /// A contract was filed in the contract certificate pool, and whether it took the place
        /// of one already there.
        ///
        /// The pool announces what is PUT into it; this announces what this service put there
        /// directly. A contract is news to a vehicle manufacturer's backend whichever door it
        /// came through.
        /// </summary>
        public event Func<SignedContractData, Boolean, Task>?  OnContractStored;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Certificate Provisioning Service.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Signers">An optional store of signing certificates, otherwise an empty in-memory one.</param>
        /// <param name="Codec">An optional ISO 15118 codec, otherwise the test one.</param>
        /// <param name="ContractCertificatePool">Where to file signed contracts.</param>
        /// <param name="Vehicles">Where the vehicles are.</param>
        /// <param name="ContractCertificateIssuer">How to issue a contract certificate.</param>
        /// <param name="RootCertificates">An optional source of trust anchors.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        /// <param name="SignerDiscoveryPath">An optional path for the un-prefixed signer discovery.</param>
        public CPS_HTTPAPI(HTTPServer                          HTTPServer,
                           ICpsSignerStore?                    Signers                     = null,
                           IContractDataCodec?                 Codec                       = null,
                           IContractDataStore?                 ContractCertificatePool     = null,
                           IProvisioningCertificateStore?      Vehicles                    = null,
                           ContractCertificateIssuerDelegate?  ContractCertificateIssuer   = null,
                           IRootCertificateStore?              RootCertificates            = null,
                           IAccessTokenValidator?              AccessTokenValidator        = null,
                           HTTPPath?                           RootPath                    = null,
                           HTTPPath?                           SignerDiscoveryPath         = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Certificate Provisioning Service"))

        {

            this.Signers                    = Signers ?? new InMemoryCpsSignerStore();
            this.Codec                      = Codec   ?? new TestContractDataCodec();
            this.ContractCertificatePool    = ContractCertificatePool;
            this.Vehicles                   = Vehicles;
            this.ContractCertificateIssuer  = ContractCertificateIssuer;
            this.RootCertificates           = RootCertificates;

            RegisterURLTemplates();

            // The one operation the specification puts outside the version prefix needs a mount
            // of its own: an API's routes are relative to where it sits, and cannot reach above it.
            this.SignerDiscovery            = new CpsSignerDiscovery_HTTPAPI(
                                                  HTTPServer,
                                                  this,
                                                  SignerDiscoveryPath ?? DefaultSignerDiscoveryPath
                                              );

        }

        #endregion


        #region (static) IssuedBy(MobilityOperatorCA, Algorithm = null)

        /// <summary>
        /// Issue contract certificates under the given authority - the mobility operator Sub-CA 2
        /// below the V2G root, in the specification's own description of this path.
        /// </summary>
        /// <param name="MobilityOperatorCA">The issuing authority, together with its key.</param>
        /// <param name="Algorithm">The curve to generate contract keys on, or the authority's own.</param>
        /// <remarks>
        /// The certificate is issued to expire when the contract does. Its validity <em>begins</em>
        /// at issuance rather than at the contract's start date, because the certificate factory
        /// takes a lifetime rather than a window - a deployment that has to honour a future start
        /// exactly supplies its own <see cref="ContractCertificateIssuerDelegate"/>, which is what
        /// one signing in an HSM would do anyway.
        /// </remarks>
        public static ContractCertificateIssuerDelegate IssuedBy(IssuedCertificate    MobilityOperatorCA,
                                                                 SignatureAlgorithm?  Algorithm   = null)

            => (emaId, contractBegins, contractEnds) => {

                   var algorithm  = Algorithm ?? MobilityOperatorCA.Certificate.SignatureAlgorithm ?? SignatureAlgorithm.secp256r1;

                   var keyPair    = algorithm == SignatureAlgorithm.ed448
                                        ? PKIFactory.GenerateEd448KeyPair()
                                        : PKIFactory.GenerateECCKeyPair(algorithm.ToString());

                   var lifeTime   = contractEnds - DateTimeOffset.UtcNow;

                   if (lifeTime <= TimeSpan.Zero)
                       return null;

                   return new IssuedCertificate(
                              PnCCertificate.From(
                                  PKIFactory.SignClientCertificate(
                                      emaId.ToString(),
                                      keyPair.Public,
                                      MobilityOperatorCA.PrivateKey,
                                      MobilityOperatorCA.Certificate.BouncyCastleCertificate,
                                      lifeTime
                                  )
                              ),
                              keyPair,
                              MobilityOperatorCA
                          );

               };

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region PUT     ~/v1/cps/contractData/signed              signContractData

            AddHandler(
                HTTPMethod.PUT,
                Route("contractData/signed"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    // This operation declares no security at all in the interface document,
                    // which is an omission rather than an intention - the rights matrix beside it
                    // gives it to mobility operators with their own PKI, and that is enforced.
                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.MO, OPCPRole.MO_ExternalPKI))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!SignedContractDataRequest.TryParse(json, out var signRequest, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    // Naming a vehicle is what asks for the result to be filed. Saying nothing
                    // means the operator will file it itself, or has another pool in mind.
                    return await Sign(request,
                                      signRequest,
                                      tokenInfo,
                                      FileInPool:   signRequest.PCID.HasValue,
                                      SuccessCode:  HTTPStatusCode.Created,
                                      WithBody:     true);

                }
            );

            #endregion

            #region PUT     ~/v1/cps/signedContractData               createSignedContractData [deprecated]

            AddHandler(
                HTTPMethod.PUT,
                Route("signedContractData"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.MO, OPCPRole.MO_ExternalPKI))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!SignedContractDataRequest.TryParse(json, out var signRequest, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    // The deprecated pair insist on both identifiers, where their replacement
                    // reads the contract off the certificate and treats the vehicle as a choice.
                    if (!signRequest.PCID.HasValue)
                        return Refuse(request, HTTPStatusCode.BadRequest, "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"");

                    // Signs and nothing else: what comes back is for the operator to file, here
                    // or in another pool.
                    return await Sign(request,
                                      signRequest,
                                      tokenInfo,
                                      FileInPool:   false,
                                      SuccessCode:  HTTPStatusCode.OK,
                                      WithBody:     true);

                }
            );

            #endregion

            #region PUT     ~/v1/cps/forward/signedContractData       createAndForwardSignedContractData [deprecated]

            AddHandler(
                HTTPMethod.PUT,
                Route("forward/signedContractData"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.MO, OPCPRole.MO_ExternalPKI))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!SignedContractDataRequest.TryParse(json, out var signRequest, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    if (!signRequest.PCID.HasValue)
                        return Refuse(request, HTTPStatusCode.BadRequest, "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"");

                    // Signs and files, and answers with an empty object: the operator asked for
                    // the contract to be put where its cars will find it, not for a copy.
                    return await Sign(request,
                                      signRequest,
                                      tokenInfo,
                                      FileInPool:   true,
                                      SuccessCode:  HTTPStatusCode.Created,
                                      WithBody:     false);

                }
            );

            #endregion

            #region PUT     ~/v1/cps/generate/signedContractData      generateSignedContractData

            AddHandler(
                HTTPMethod.PUT,
                Route("generate/signedContractData"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.MO, OPCPRole.MO_V2GPKI))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!GenerateSignedContractDataRequest.TryParse(json, out var generateRequest, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    return await Generate(request, generateRequest, tokenInfo);

                }
            );

            #endregion

            #region GET     ~/v1/cps/signer                           getAllCpsSigners

            // The specification's own path for this is /cps/signer, without the version prefix
            // every other operation of this service carries. It is served there too - see
            // SignerDiscovery - and here, because a caller that assumes the prefix is not wrong.
            AddHandler(
                HTTPMethod.GET,
                Route("signer"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: GetAllCpsSigners
            );

            #endregion

        }

        #endregion


        #region GetAllCpsSigners(Request)

        /// <summary>
        /// List the certificates this service can sign with, and the V2G roots they chain up to.
        ///
        /// Everything published here is read off the certificates themselves, so a listed signer
        /// cannot describe itself incorrectly - and no private key can appear in it, because the
        /// published shape has nowhere to put one.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        public async Task<HTTPResponse> GetAllCpsSigners(HTTPRequest Request)
        {

            if (!TryAuthenticate(Request, out var tokenInfo, out var response))
                return response;

            if (!TryAuthorize(Request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.CPO, OPCPRole.CPS,
                                                                OPCPRole.MO,  OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                return response;

            return Respond(
                       Request,
                       HTTPStatusCode.OK,
                       CPSEnvelope.WrapMany(
                           (await Signers.GetAll()).Select(signer => CpsSigner.From(signer))
                       )
                   );

        }

        #endregion


        #region (private) Sign    (Request, SignRequest, TokenInfo, FileInPool, SuccessCode, WithBody)

        /// <summary>
        /// The three operations that sign contract data an operator brought, which differ only in
        /// what happens to the result.
        /// </summary>
        private async Task<HTTPResponse> Sign(HTTPRequest                Request,
                                              SignedContractDataRequest  SignRequest,
                                              OPCPTokenInfo              TokenInfo,
                                              Boolean                    FileInPool,
                                              HTTPStatusCode             SuccessCode,
                                              Boolean                    WithBody)
        {

            #region Which contract this is

            var emaId = SignRequest.Contract;

            if (!emaId.HasValue)
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "emaid : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"");

            // The specification says the EMAID "needs to fit to the common name in the contract
            // certificate". Where a request states both and they disagree, one of them is a
            // mistake and signing either would make it permanent.
            if (SignRequest.EMAId.HasValue &&
                SignRequest.ContractData.Contract.HasValue &&
                SignRequest.EMAId.Value != SignRequest.ContractData.Contract.Value)
            {
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              $"The given EMAID '{SignRequest.EMAId.Value}' is not the common name of the contract certificate!");
            }

            if (AccessTokenValidator is not null && !TokenInfo.MayActFor(emaId.Value))
                return Refuse(Request,
                              HTTPStatusCode.Forbidden,
                              $"The given token is not authorized for the e-mobility provider '{emaId.Value.ProviderId}'!");

            #endregion

            #region The chain the operator brought, if this service checks them

            if (RootCertificates is not null)
            {

                var roots  = (await RootCertificates.GetAll(RootCertificateType.MO)).
                                 Concat(await RootCertificates.GetAll(RootCertificateType.V2G)).
                                 Select(rootCertificate => rootCertificate.Certificate).
                                 ToArray();

                var result = PnCChainValidator.ValidateContractCertificate(
                                 SignRequest.ContractData.ContractCertificate,
                                 SignRequest.ContractData.SubCAs,
                                 roots,
                                 emaId.Value
                             );

                if (!result.IsValid)
                    return Refuse(Request, HTTPStatusCode.BadRequest, result.Reason);

            }

            #endregion

            #region A certificate to sign with

            var (signer, refusal) = await SelectSigner(Request, SignRequest.CpsV2GRootCertificateFingerprint);

            if (signer is null)
                return refusal!;

            #endregion

            var signedData = Codec.SignContractData(
                                 SignRequest.ContractData,
                                 emaId.Value,
                                 SignRequest.PCID,
                                 signer.Certificate,
                                 signer.PrivateKey
                             );

            #region File it, when that is what was asked for

            if (FileInPool)
            {

                if (!SignRequest.PCID.HasValue)
                    return Refuse(Request,
                                  HTTPStatusCode.BadRequest,
                                  "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"");

                var filed = await FileContract(
                                      emaId.Value,
                                      SignRequest.PCID.Value,
                                      signedData,
                                      SignRequest.XSDMsgDefNamespace,
                                      SignRequest.Metadata,
                                      signer,
                                      SignRequest.ContractData.ContractCertificate
                                  );

                if (filed is not null)
                    return Refuse(Request, filed.Value.StatusCode, filed.Value.Reason);

            }

            #endregion

            return Respond(
                       Request,
                       SuccessCode,
                       WithBody
                           ? new SignedContractDataResponse(
                                 emaId.Value,
                                 signedData,
                                 SignRequest.XSDMsgDefNamespace,
                                 SignRequest.PCID,
                                 signer.Root.Certificate.SHA256Fingerprint,
                                 signer.Root.Certificate.SubjectName,
                                 SignRequest.Metadata
                             ).ToJSON()

                           // An empty object, which is what the specification documents for the
                           // operation that files rather than answers.
                           : new JObject()
                   );

        }

        #endregion

        #region (private) Generate(Request, GenerateRequest, TokenInfo)

        /// <summary>
        /// The operation for a mobility operator without a PKI of its own: the contract
        /// certificate is issued here, its key wrapped for the car, and the result filed.
        ///
        /// It is the only place in the protocol where all three pools meet - the vehicle comes
        /// from the provisioning certificate pool, the signature from a certificate anchored in
        /// the root certificate pool, and the result goes into the contract certificate pool.
        /// </summary>
        private async Task<HTTPResponse> Generate(HTTPRequest                        Request,
                                                  GenerateSignedContractDataRequest  GenerateRequest,
                                                  OPCPTokenInfo                      TokenInfo)
        {

            #region A contract that is over before it starts

            if (GenerateRequest.ContractEnds <= DateTimeOffset.UtcNow)
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "The given contractEnds date is in the past.");

            if (GenerateRequest.ContractEnds <= GenerateRequest.ContractBegins)
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "The given contractEnds date is not after the given contractBegins date.");

            if (AccessTokenValidator is not null && !TokenInfo.MayActFor(GenerateRequest.EMAId))
                return Refuse(Request,
                              HTTPStatusCode.Forbidden,
                              $"The given token is not authorized for the e-mobility provider '{GenerateRequest.EMAId.ProviderId}'!");

            #endregion

            #region The car, whose public key the contract's private key is wrapped against

            if (Vehicles is null)
                return Refuse(Request,
                              HTTPStatusCode.InternalServerError,
                              "This contract provisioning service has no access to a provisioning certificate pool!");

            var vehicle = await Vehicles.Get(GenerateRequest.PCID);

            if (vehicle is null)
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "The OEM provisioning certificate with the given PCID is not available.");

            #endregion

            #region A certificate to sign with, and an authority to issue with

            var (signer, refusal) = await SelectSigner(Request, GenerateRequest.CpsV2GRootCertificateFingerprint);

            if (signer is null)
                return refusal!;

            if (ContractCertificateIssuer is null)
                return Refuse(Request,
                              HTTPStatusCode.InternalServerError,
                              "This contract provisioning service operates no mobility operator certification authority!");

            var contract = ContractCertificateIssuer(GenerateRequest.EMAId,
                                                     GenerateRequest.ContractBegins,
                                                     GenerateRequest.ContractEnds);

            if (contract is null)
                return Refuse(Request,
                              HTTPStatusCode.InternalServerError,
                              $"No contract certificate could be issued for '{GenerateRequest.EMAId}'!");

            #endregion

            #region Wrap the contract's key for this car, and sign the lot

            var wrapped     = ContractKeyCrypto.Wrap(contract.PrivateKey,
                                                     vehicle.VehicleCertificate);

            var subCAs      = contract.SubCAs.ToArray();

            if (subCAs.Length == 0)
                return Refuse(Request,
                              HTTPStatusCode.InternalServerError,
                              "The issued contract certificate has no certification authority above it!");

            var contractData = new ContractData(
                                   contract.Certificate,
                                   subCAs[^1],
                                   wrapped.EncryptedPrivateKey,
                                   wrapped.DHPublicKey,
                                   subCAs.Length > 1 ? subCAs[0] : null,
                                   GenerateRequest.EMAId
                               );

            var signedData   = Codec.SignContractData(
                                   contractData,
                                   GenerateRequest.EMAId,
                                   GenerateRequest.PCID,
                                   signer.Certificate,
                                   signer.PrivateKey
                               );

            #endregion

            var filed = await FileContract(
                                  GenerateRequest.EMAId,
                                  GenerateRequest.PCID,
                                  signedData,
                                  GenerateRequest.XSDMsgDefNamespace,
                                  GenerateRequest.Metadata,
                                  signer,
                                  contract.Certificate
                              );

            if (filed is not null)
                return Refuse(Request, filed.Value.StatusCode, filed.Value.Reason);

            // Created, and nothing to say: the operator asked for a contract to exist where its
            // cars will find it, and it now does.
            return Respond(Request, HTTPStatusCode.Created);

        }

        #endregion


        #region (private) SelectSigner(Request, Fingerprint)

        /// <summary>
        /// Pick the certificate to sign with: the one anchored to the V2G root the operator named,
        /// or - when it named none - whichever this service prefers.
        /// </summary>
        /// <returns>The signer, or why there is none.</returns>
        /// <remarks>
        /// Naming a root this service cannot sign under is the operator's mistake and gets a 400;
        /// having no signing certificate at all is this service's, and gets a 500. Signing under
        /// some other root instead would produce contract data the cars this operator asked about
        /// cannot verify.
        /// </remarks>
        private async Task<(IssuedCertificate? Signer, HTTPResponse? Response)>
            SelectSigner(HTTPRequest  Request,
                         String?      Fingerprint)
        {

            var signer = await Signers.Get(Fingerprint);

            if (signer is not null)
                return (signer, null);

            return (null,
                    Fingerprint.IsNotNullOrEmpty()

                        ? Refuse(Request,
                                 HTTPStatusCode.BadRequest,
                                 $"This contract provisioning service has no signing certificate under the V2G root '{Fingerprint}'!")

                        : Refuse(Request,
                                 HTTPStatusCode.InternalServerError,
                                 "This contract provisioning service has no signing certificate!"));

        }

        #endregion

        #region (private) FileContract(EMAId, PCID, SignedData, XSDMsgDefNamespace, Metadata, Signer, ContractCertificate)

        /// <summary>
        /// Put a signed contract into the pool.
        /// </summary>
        /// <returns>Nothing when it was filed, and why not when it was not.</returns>
        private async Task<(HTTPStatusCode StatusCode, String Reason)?>
            FileContract(EMA_Id               EMAId,
                         PCID                 PCID,
                         Byte[]               SignedData,
                         XSD_MsgDefNamespace  XSDMsgDefNamespace,
                         String?              Metadata,
                         IssuedCertificate    Signer,
                         PnCCertificate       ContractCertificate)
        {

            if (ContractCertificatePool is null)
                return (HTTPStatusCode.InternalServerError,
                        "This contract provisioning service has no access to a contract certificate pool!");

            // A contract belongs to one car. Letting a second car claim an EMAID already in use
            // would take the contract away from the first one, which nobody asked for.
            var existing = await ContractCertificatePool.Get(EMAId);

            if (existing is not null && existing.PCID != PCID)
                return (HTTPStatusCode.BadRequest,
                        "Invalid Tupple - EMAID is already used by other PCID.");

            var stored = await ContractCertificatePool.Add(
                                   new SignedContractData(
                                       EMAId,
                                       PCID,
                                       SignedData,
                                       XSDMsgDefNamespace,
                                       Metadata,
                                       Signer.Root.Certificate.SHA256Fingerprint,
                                       ContractCertificate: ContractCertificate
                                   )
                               );

            if (OnContractStored is not null)
                await OnContractStored.Invoke(stored, existing is not null);

            return null;

        }

        #endregion

    }


    /// <summary>
    /// The one Certificate Provisioning Service operation the specification puts outside the
    /// version prefix: <c>GET /cps/signer</c>, where everything else is under <c>/v1/cps</c>.
    ///
    /// It needs a mount of its own, because an API's routes are relative to where it sits and
    /// cannot reach above it. It serves the same handler as the prefixed route beside it.
    /// </summary>
    public class CpsSignerDiscovery_HTTPAPI : AOPCPHTTPAPI
    {

        #region Properties

        /// <summary>
        /// The service whose signers are listed here.
        /// </summary>
        public CPS_HTTPAPI CPS { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Serve the signer discovery of the given service at an un-prefixed path.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="CPS">The service whose signers are to be listed.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public CpsSignerDiscovery_HTTPAPI(HTTPServer   HTTPServer,
                                          CPS_HTTPAPI  CPS,
                                          HTTPPath?    RootPath   = null)

            : base(HTTPServer,
                   CPS.AccessTokenValidator,
                   RootPath ?? CPS_HTTPAPI.DefaultSignerDiscoveryPath,
                   I18NString.Create("OPCP Certificate Provisioning Service signer discovery"))

        {

            this.CPS = CPS ?? throw new ArgumentNullException(nameof(CPS));

            AddHandler(
                HTTPMethod.GET,
                Route("signer"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: this.CPS.GetAllCpsSigners
            );

        }

        #endregion

    }

}
