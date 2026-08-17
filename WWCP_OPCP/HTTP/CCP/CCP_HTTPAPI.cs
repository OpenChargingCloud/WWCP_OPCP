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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A Contract Certificate Pool: the contracts waiting for the cars they belong to to plug in.
    ///
    /// A charge point operator asks it what to install when a vehicle presents itself, a contract
    /// provisioning service fills it, a mobility operator deletes from it, and a vehicle
    /// manufacturer reads what its cars have.
    /// </summary>
    public class CCP_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the Contract Certificate Pool is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/v1/ccp/");

        #endregion

        #region Properties

        /// <summary>
        /// Where this pool keeps its contracts.
        /// </summary>
        public IContractDataStore   Store    { get; }

        /// <summary>
        /// What reads and writes the ISO 15118 structures the pool moves without looking inside.
        /// </summary>
        public IContractDataCodec   Codec    { get; }

        #endregion

        #region Events

        /// <summary>
        /// A vehicle lost the contract it charges under by default, and no other was promoted.
        ///
        /// The specification is deliberate about this: deleting the default does not pick a new
        /// one, because the pool choosing which contract a car charges under is not the pool's
        /// decision to make. The manufacturer is told instead.
        /// </summary>
        public event Func<PCID, EMA_Id, Task>?  OnDefaultContractLost;

        /// <summary>
        /// A contract was filed, and whether it took the place of one already there.
        ///
        /// The webhook service listens for this: a vehicle manufacturer's backend acts on a
        /// contract appearing for one of its cars.
        /// </summary>
        public event Func<SignedContractData, Boolean, Task>?  OnContractStored;

        /// <summary>
        /// A contract was deleted.
        /// </summary>
        public event Func<SignedContractData, Task>?           OnContractRemoved;

        /// <summary>
        /// A contract actually reached a car - installed through a charging station, or collected
        /// by a manufacturer's backend. The end of the whole story, and the one event that says
        /// the contract is in use rather than merely on file.
        /// </summary>
        public event Func<SignedContractData, Task>?           OnContractDelivered;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Contract Certificate Pool.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Codec">An optional ISO 15118 codec, otherwise the test one.</param>
        /// <param name="Store">An optional store, otherwise an in-memory one.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public CCP_HTTPAPI(HTTPServer              HTTPServer,
                           IContractDataCodec?     Codec                  = null,
                           IContractDataStore?     Store                  = null,
                           IAccessTokenValidator?  AccessTokenValidator   = null,
                           HTTPPath?               RootPath               = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Contract Certificate Pool"))

        {

            this.Store  = Store ?? new InMemoryContractDataStore();
            this.Codec  = Codec ?? new TestContractDataCodec();

            RegisterURLTemplates();

        }

        #endregion


        #region AttachTo(ProvisioningCertificatePool)

        /// <summary>
        /// Listen to a Provisioning Certificate Pool, and follow what happens to its vehicles.
        /// </summary>
        /// <param name="ProvisioningCertificatePool">The provisioning certificate pool to follow.</param>
        /// <remarks>
        /// Both cases mean the same thing: the car can no longer prove it is the car these
        /// contracts were written for. Leaving them in the pool would leave them to fail at a
        /// charging station instead, which is a worse place to find out.
        /// </remarks>
        public void AttachTo(PCP_HTTPAPI ProvisioningCertificatePool)
        {

            ProvisioningCertificatePool.OnProvisioningCertificateDeleted += async (pcid, certificate)
                => await Store.RemoveByVehicle(pcid);

            ProvisioningCertificatePool.OnVehicleKeyChanged              += async (pcid, certificate)
                => await Store.RemoveByVehicle(pcid);

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region POST    ~/v1/ccp/signedContractData                    getSignedContractData

            AddHandler(
                HTTPMethod.POST,
                Route("signedContractData"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.CPO))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    // Default true: an operator that says nothing gets an answer its charging
                    // station can pass on.
                    var alwaysReturnEXI = ReadBooleanHeader(request, CCP_HTTPClient.AlwaysReturnEXIHeader, true);

                    #region Read what the vehicle asked for

                    var requestText = json.Value<String>("certificateInstallationReq");

                    if (requestText.IsNullOrEmpty())
                        return Refuse(request, HTTPStatusCode.BadRequest, "EXI format is invalid!");

                    Byte[] installationRequest;

                    try
                    {
                        installationRequest = Convert.FromBase64String(requestText!);
                    }
                    catch
                    {
                        return Refuse(request, HTTPStatusCode.BadRequest, "EXI format is invalid!");
                    }

                    if (!Codec.TryDecodeInstallationRequest(installationRequest, out var decoded, out var decodeError))
                        return Refuse(request, HTTPStatusCode.BadRequest, decodeError);

                    #endregion

                    #region Pick a contract

                    var contracts = await Store.GetByVehicle(decoded.PCID);

                    // What the vehicle asked for first, if it has it; otherwise its default.
                    // For ISO 15118-2 exactly one contract goes back, which is why the array
                    // below never has more than one member - it is preparation for -20.
                    var chosen    = decoded.PrioritizedEMAIds.
                                        Select(emaId => contracts.FirstOrDefault(contract => contract.EMAId == emaId)).
                                        FirstOrDefault(contract => contract is not null)
                                    ?? contracts.FirstOrDefault(contract => contract.IsDefault);

                    #endregion

                    #region Nothing to install

                    if (chosen is null)
                    {

                        if (!alwaysReturnEXI)
                            return Refuse(request, HTTPStatusCode.NotFound, "Contract or Vehicle not found.");

                        // An HTTP 404 whose body is a perfectly good ISO 15118 response. The
                        // charging station relaying it speaks ISO 15118, not HTTP, and has to
                        // be given something it can pass on to the car.
                        return Respond(request,
                                       HTTPStatusCode.NotFound,
                                       WrapInstallation(Codec.EncodeNegativeResponse("Contract or Vehicle not found."),
                                                        null));

                    }

                    #endregion

                    if (!Codec.TryEncodeInstallationResponse(chosen.SignedContractDataXML, out var installationResponse, out var encodeError))
                        return Refuse(request, HTTPStatusCode.InternalServerError, encodeError);

                    // The end of the whole story: a contract left the pool for the car it was
                    // written for.
                    if (OnContractDelivered is not null)
                        await OnContractDelivered.Invoke(chosen);

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   WrapInstallation(installationResponse, chosen));

                }
            );

            #endregion

            #region PUT     ~/v1/ccp/signedContractData                    addSignedContractData

            AddHandler(
                HTTPMethod.PUT,
                Route("signedContractData"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.CPS))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!SignedContractData.TryParse(json, out var contractData, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    // The pool reads what it was handed - both to check that the signature is
                    // real and to learn what it is holding, none of which the request states.
                    if (!Codec.TryReadSignedContractData(contractData.SignedContractDataXML, out var inner, out var readError))
                        return Refuse(request, HTTPStatusCode.BadRequest, readError);

                    var replaced = await Store.Get(contractData.EMAId) is not null;

                    var stored   = await Store.Add(contractData.With(ContractCertificate: inner.ContractCertificate));

                    if (OnContractStored is not null)
                        await OnContractStored.Invoke(stored, replaced);

                    return Respond(request, HTTPStatusCode.Created, stored.ToContractInfo());

                }
            );

            #endregion

            #region DELETE  ~/v1/ccp/signedContractData/{emaid}            deleteSignedContractData

            AddHandler(
                HTTPMethod.DELETE,
                // The specification puts three different things at this position: an EMAID to
                // delete, a PCID to list, and a PCID that starts a longer path. A route tree
                // cannot hold two names for one segment, so they share one and each handler
                // reads it as what its own operation means.
                Route("signedContractData/{id}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.MO,
                                                                        OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                        return response;

                    if (!TryParseURLParameter<EMA_Id>(request, "id", EMA_Id.TryParse,
                                                      "EMAID", out var emaId, out response))
                        return response;

                    if (AccessTokenValidator is not null && !tokenInfo.MayActFor(emaId))
                        return Refuse(request,
                                      HTTPStatusCode.Forbidden,
                                      $"The given token is not authorized for the e-mobility provider '{emaId.ProviderId}'!");

                    var removed = await Store.Remove(emaId);

                    if (removed is null)
                        return Refuse(request,
                                      HTTPStatusCode.NotFound,
                                      "The contract for the given EMAID not found.");

                    if (OnContractRemoved is not null)
                        await OnContractRemoved.Invoke(removed);

                    // Deleting the default leaves the vehicle without one, on purpose.
                    if (removed.IsDefault && OnDefaultContractLost is not null)
                        await OnDefaultContractLost.Invoke(removed.PCID, removed.EMAId);

                    return Respond(request, HTTPStatusCode.OK);

                }
            );

            #endregion

            #region GET     ~/v1/ccp/provideSignedContractData/{emaid}/{pcid}   provideSignedContractData

            AddHandler(
                HTTPMethod.GET,
                Route("provideSignedContractData/{emaid}/{pcid}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM))
                        return response;

                    if (!TryParseURLParameter<EMA_Id>(request, "emaid", EMA_Id.TryParse,
                                                      "EMAID", out var emaId, out response))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "pcid", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    var contract = await Store.Get(emaId);

                    if (contract is null || contract.PCID != pcid)
                        return Refuse(request,
                                      HTTPStatusCode.NotFound,
                                      "The contract for the given EMAID not found.");

                    if (!Codec.TryEncodeInstallationResponse(contract.SignedContractDataXML, out var installationResponse, out var encodeError))
                        return Refuse(request, HTTPStatusCode.InternalServerError, encodeError);

                    // Flat, not wrapped: a different operation with a different shape, and the
                    // manufacturer still has to make the ISO checks itself before handing this
                    // to a car.
                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   JSONObject.Create(
                                       new JProperty("certificateInstallationRes",  Convert.ToBase64String(installationResponse)),
                                       new JProperty("xsdMsgDefNamespace",          contract.XSDMsgDefNamespace.ToString()),
                                       contract.CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty()
                                           ? new JProperty("cpsV2GRootCertificateFingerprint", contract.CpsV2GRootCertificateFingerprint)
                                           : null
                                   ));

                }
            );

            #endregion

            #region POST    ~/v1/ccp/signedContractData/{pcid}/{emaid}/default   setDefaultContract

            AddHandler(
                HTTPMethod.POST,
                Route("signedContractData/{id}/{emaid}/default"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "id", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    if (!TryParseURLParameter<EMA_Id>(request, "emaid", EMA_Id.TryParse,
                                                      "EMAID", out var emaId, out response))
                        return response;

                    return await Store.SetDefault(pcid, emaId)

                               ? Respond(request, HTTPStatusCode.OK)

                               : Refuse(request,
                                        HTTPStatusCode.BadRequest,
                                        "The contract for the given EMAID not found.");

                }
            );

            #endregion

            #region GET     ~/v1/ccp/lookupContract/{emaid}                lookupContract

            AddHandler(
                HTTPMethod.GET,
                Route("lookupContract/{emaid}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.CPO,
                                                                        OPCPRole.MO, OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                        return response;

                    if (!TryParseURLParameter<EMA_Id>(request, "emaid", EMA_Id.TryParse,
                                                      "EMAID", out var emaId, out response))
                        return response;

                    var contract = await Store.Get(emaId);

                    if (contract is null)
                        return Refuse(request,
                                      HTTPStatusCode.NotFound,
                                      "The contract for the given EMAID not found.");

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   WrapContracts([ contract ]));

                }
            );

            #endregion

            #region GET     ~/v1/ccp/signedContractData/{pcid}             getContracts

            AddHandler(
                HTTPMethod.GET,
                Route("signedContractData/{id}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "id", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   WrapContracts(await Store.GetByVehicle(pcid)));

                }
            );

            #endregion

        }

        #endregion


        #region (private, static) WrapInstallation(Response, Contract)

        /// <summary>
        /// The shape the hot path answers in: a CCPResponse around an array of one entry per
        /// contract, each with a messageDef inside it.
        /// </summary>
        private static JObject WrapInstallation(Byte[]               Response,
                                                SignedContractData?  Contract)

            => new (
                   new JProperty("CCPResponse",
                       new JObject(
                           new JProperty("emaidContent",
                               new JArray(
                                   new JObject(
                                       new JProperty("messageDef",
                                           JSONObject.Create(

                                               new JProperty("certificateInstallationRes",  Convert.ToBase64String(Response)),

                                               Contract is not null
                                                   ? new JProperty("emaid",                 Contract.EMAId.ToString())
                                                   : null,

                                               Contract?.Metadata.IsNotNullOrEmpty() == true
                                                   ? new JProperty("metaData",              Contract.Metadata)
                                                   : null,

                                               Contract?.CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty() == true
                                                   ? new JProperty("cpsV2GRootCertificateFingerprint", Contract.CpsV2GRootCertificateFingerprint)
                                                   : null

                                           ))
                                   )
                               ))
                       ))
               );

        #endregion

        #region (private, static) WrapContracts(Contracts)

        /// <summary>
        /// The shape a lookup answers in.
        /// </summary>
        private static JObject WrapContracts(IEnumerable<SignedContractData> Contracts)

            => new (
                   new JProperty("XMLContracts",
                       new JArray(Contracts.Select(contract => contract.ToContractInfo())))
               );

        #endregion

        #region (private, static) ReadBooleanHeader(Request, Name, Default)

        private static Boolean ReadBooleanHeader(HTTPRequest  Request,
                                                 String       Name,
                                                 Boolean      Default)
        {

            var value = Request.GetHeaderField(Name);

            return value.IsNullOrEmpty()
                       ? Default
                       : value!.Trim().Equals("true", StringComparison.OrdinalIgnoreCase);

        }

        #endregion

    }

}
