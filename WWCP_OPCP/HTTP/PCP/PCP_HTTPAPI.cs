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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Ask whether a certificate has been revoked.
    /// </summary>
    /// <param name="Certificate">The certificate to ask about.</param>
    /// <param name="Issuer">The authority that issued it.</param>
    /// <param name="CancellationToken">A token to cancel the request.</param>
    public delegate Task<OCSPResult> RevocationCheckDelegate(PnCCertificate     Certificate,
                                                             PnCCertificate     Issuer,
                                                             CancellationToken  CancellationToken);


    /// <summary>
    /// A Provisioning Certificate Pool: the certificate a vehicle was born with, published by its
    /// manufacturer and read by whichever mobility operator is about to write it a contract.
    ///
    /// A manufacturer may publish and depublish only its own vehicles, which is decided by the
    /// World Manufacturer Identifier the PCID begins with.
    /// </summary>
    public class PCP_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the Provisioning Certificate Pool is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/v1/oem/");

        #endregion

        #region Properties

        /// <summary>
        /// Where this pool keeps its vehicles.
        /// </summary>
        public IProvisioningCertificateStore  Store               { get; }

        /// <summary>
        /// Where the trust anchors come from. A provisioning certificate is only acceptable if it
        /// chains to a manufacturer root the ecosystem has admitted.
        /// </summary>
        public IRootCertificateStore          RootCertificates    { get; }

        /// <summary>
        /// How this pool checks revocation.
        /// </summary>
        /// <remarks>
        /// Optional, and when it is absent the third step of the validation is not performed. That
        /// is a deliberate escape hatch for a development ecosystem with no responder running, and
        /// a hole anywhere else - the specification makes this check mandatory both when a
        /// certificate is published and when it is handed out.
        /// </remarks>
        public RevocationCheckDelegate?       RevocationCheck     { get; }

        #endregion

        #region Events

        /// <summary>
        /// A vehicle's provisioning certificate was depublished.
        ///
        /// The contract certificate pool listens for this: every contract belonging to the vehicle
        /// has to go with it, and contracts issued by an operator-owned authority are revoked.
        /// </summary>
        public event Func<PCID, ProvisioningCertificate, Task>?  OnProvisioningCertificateDeleted;

        /// <summary>
        /// A vehicle was republished with a different key pair - the workshop case.
        ///
        /// Every contract issued against the old key is worthless, so the contract certificate pool
        /// deletes them rather than leave them to fail at a charging station.
        /// </summary>
        public event Func<PCID, ProvisioningCertificate, Task>?  OnVehicleKeyChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Provisioning Certificate Pool.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="RootCertificates">Where the trust anchors come from.</param>
        /// <param name="Store">An optional store, otherwise an in-memory one.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RevocationCheck">An optional revocation check.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public PCP_HTTPAPI(HTTPServer                     HTTPServer,
                           IRootCertificateStore          RootCertificates,
                           IProvisioningCertificateStore? Store                  = null,
                           IAccessTokenValidator?         AccessTokenValidator   = null,
                           RevocationCheckDelegate?       RevocationCheck        = null,
                           HTTPPath?                      RootPath               = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Provisioning Certificate Pool"))

        {

            this.RootCertificates  = RootCertificates ?? throw new ArgumentNullException(nameof(RootCertificates));
            this.Store             = Store ?? new InMemoryProvisioningCertificateStore();
            this.RevocationCheck   = RevocationCheck;

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region PUT     ~/v1/oem/provCerts                        addOEMProvCert

            AddHandler(
                HTTPMethod.PUT,
                Route("provCerts"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!ProvisioningCertificate.TryParse(json, out var certificate, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    var validation = await Validate(certificate, tokenInfo, request.CancellationToken);

                    if (validation.Response is not null)
                        return validation.Response(request);

                    var stored = await Store.Add(certificate.WithRoot(validation.Root!));

                    // A new key pair means every contract written against the old one is
                    // worthless. The pool does not leave those to fail at a charging station.
                    if (stored.KeyChanged && OnVehicleKeyChanged is not null)
                        await OnVehicleKeyChanged.Invoke(certificate.PCID!.Value, stored.Certificate);

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   PCPEnvelope.Wrap(stored.Certificate));

                }
            );

            #endregion

            #region GET     ~/v1/oem/provCerts/{pcid}                 getOEMProvCert

            AddHandler(
                HTTPMethod.GET,
                Route("provCerts/{pcid}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.MO,
                                                                        OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI,
                                                                        OPCPRole.CPS))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "pcid", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    var certificate = await Store.Get(pcid);

                    if (certificate is null)
                        return Refuse(request,
                                      HTTPStatusCode.NotFound,
                                      "The OEM provisioning certificate with given PCID is not found.");

                    // Re-checked on the way out, not only on the way in: a certificate that has
                    // been revoked since it was published must not be handed to an operator that
                    // is about to write a contract against it.
                    var validation = await Validate(certificate, null, request.CancellationToken);

                    if (validation.Response is not null)
                        return validation.Response(request);

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   PCPEnvelope.Wrap(certificate.WithRoot(validation.Root!)));

                }
            );

            #endregion

            #region DELETE  ~/v1/oem/provCerts/{pcid}                 deleteOEMProvCert

            AddHandler(
                HTTPMethod.DELETE,
                Route("provCerts/{pcid}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "pcid", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    if (!MayActFor(tokenInfo, pcid, request, out response))
                        return response;

                    var removed = await Store.Remove(pcid);

                    if (removed is null)
                        return Refuse(request,
                                      HTTPStatusCode.NotFound,
                                      "The OEM provisioning certificate with given PCID is not found.");

                    if (OnProvisioningCertificateDeleted is not null)
                        await OnProvisioningCertificateDeleted.Invoke(pcid, removed);

                    return Respond(request, HTTPStatusCode.OK);

                }
            );

            #endregion

            #region GET     ~/v1/oem/provCerts/lookupVehicle/{pcid}   lookupVehicle

            AddHandler(
                HTTPMethod.GET,
                Route("provCerts/lookupVehicle/{pcid}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.MO,
                                                                        OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI,
                                                                        OPCPRole.CPS))
                        return response;

                    if (!TryParseURLParameter<PCID>(request, "pcid", PCID.TryParse,
                                                    "PCID", out var pcid, out response))
                        return response;

                    // A status and nothing else: this operation answers whether the pool knows
                    // the vehicle, not anything about it.
                    return await Store.Contains(pcid)

                               ? Respond(request, HTTPStatusCode.OK)

                               : Refuse(request,
                                        HTTPStatusCode.NotFound,
                                        "The OEM provisioning certificate with given PCID is not found.");

                }
            );

            #endregion

        }

        #endregion


        #region (private) Validate  (Certificate, TokenInfo, CancellationToken)

        /// <summary>
        /// The four checks the specification prescribes, in the order it prescribes them, each
        /// aborting with its own reason.
        ///
        /// ① the vehicle belongs to the manufacturer asking,
        /// ② every certificate on the path is valid now,
        /// ③ none of them has been revoked,
        /// ④ the path reaches a manufacturer root this ecosystem has admitted.
        /// </summary>
        private async Task<(PnCCertificate? Root, Func<HTTPRequest, HTTPResponse>? Response)>
            Validate(ProvisioningCertificate  Certificate,
                     OPCPTokenInfo?           TokenInfo,
                     CancellationToken        CancellationToken)
        {

            #region The certificate has to name a vehicle at all

            var pcid = Certificate.PCID;

            if (!pcid.HasValue)
                return (null, request => Refuse(request,
                                                HTTPStatusCode.BadRequest,
                                                $"pcid : must match \"^[a-zA-Z0-9]{{17,18}}$\""));

            #endregion

            #region ① The vehicle has to be the manufacturer's own

            if (TokenInfo is not null &&
                AccessTokenValidator is not null &&
               !TokenInfo.MayActFor(pcid.Value))
            {
                return (null, request => Refuse(request,
                                                HTTPStatusCode.Forbidden,
                                                $"The given token is not authorized for the World Manufacturer Identifier '{pcid.Value.WMI}'!"));
            }

            #endregion

            #region ② and ④ Validity along the whole path, up to an admitted root

            var roots  = (await RootCertificates.GetAll(RootCertificateType.OEM)).
                             Select(rootCertificate => rootCertificate.Certificate).
                             ToArray();

            var result = PnCChainValidator.ValidateProvisioningCertificate(
                             Certificate.VehicleCertificate,
                             Certificate.SubCAs,
                             roots,
                             pcid.Value,
                             DateTimeOffset.UtcNow
                         );

            if (!result.IsValid)
                return (null, request => Refuse(request,
                                                HTTPStatusCode.BadRequest,
                                                result.Reason));

            #endregion

            #region ③ Revocation, along the path that was just established

            // The specification lists revocation before the chain check. Doing it after costs
            // nothing and gains two things: a certificate that chains nowhere is refused for
            // that rather than for an unanswerable revocation question, and each certificate
            // can be asked about at its actual issuer - which is how RFC 6960 identifies a
            // certificate, and impossible to get right before the path is known.
            if (RevocationCheck is not null)
            {

                var path    = new List<PnCCertificate> { Certificate.VehicleCertificate };
                path.AddRange(Certificate.SubCAs);

                var issuers = new List<PnCCertificate>();
                issuers.AddRange(Certificate.SubCAs);
                issuers.Add(result.Anchor!);

                for (var i = 0; i < path.Count; i++)
                {

                    var status = await RevocationCheck(path[i], issuers[i], CancellationToken);

                    if (status.IsRevoked)
                        return (null, request => Refuse(request,
                                                        HTTPStatusCode.BadRequest,
                                                        $"'{path[i].CommonName}' has been revoked!"));

                    // Not knowing is not the same as good, and the specification has the pool
                    // refuse rather than publish something it could not check.
                    if (!status.IsGood)
                        return (null, request => Refuse(request,
                                                        HTTPStatusCode.BadRequest,
                                                        $"The revocation status of '{path[i].CommonName}' could not be established: {status.Reason}"));

                }

            }

            #endregion

            return (result.Anchor, null);

        }

        #endregion

        #region (private) MayActFor(TokenInfo, PCID, Request, out Response)

        /// <summary>
        /// Whether the caller may act for the vehicle behind the given PCID.
        /// </summary>
        private Boolean MayActFor(OPCPTokenInfo                           TokenInfo,
                                  PCID                                    PCID,
                                  HTTPRequest                             Request,
                                  [NotNullWhen(false)] out HTTPResponse?  Response)
        {

            Response = null;

            if (AccessTokenValidator is null || TokenInfo.MayActFor(PCID))
                return true;

            Response = Refuse(Request,
                              HTTPStatusCode.Forbidden,
                              $"The given token is not authorized for the World Manufacturer Identifier '{PCID.WMI}'!");

            return false;

        }

        #endregion

    }

}
