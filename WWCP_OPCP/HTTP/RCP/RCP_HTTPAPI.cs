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
    /// A Root Certificate Pool: the trust anchors of a Plug&amp;Charge ecosystem, and the one
    /// service every other component reads from.
    ///
    /// Reading is open to every role. Writing is not open to any of them - admitting or removing
    /// a trust anchor is reserved for an administrator of the ecosystem itself, because it decides
    /// what every participant will believe.
    /// </summary>
    public class RCP_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the Root Certificate Pool is mounted.
        ///
        /// Each OPCP service is its own HTTP API under its own path - Hermod allows one API per
        /// path, and the six services of an ecosystem are six APIs. A deployment living under a
        /// path prefix of its own passes the whole mount path instead.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/v1/root");

        #endregion

        #region Properties

        /// <summary>
        /// Where this pool keeps its trust anchors.
        /// </summary>
        public IRootCertificateStore  Store    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Root Certificate Pool.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Store">An optional store, otherwise an in-memory one.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public RCP_HTTPAPI(HTTPServer              HTTPServer,
                           IRootCertificateStore?  Store                  = null,
                           IAccessTokenValidator?  AccessTokenValidator   = null,
                           HTTPPath?               RootPath               = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Root Certificate Pool"))

        {

            this.Store = Store ?? new InMemoryRootCertificateStore();

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region GET     ~/v1/root/rootCerts/{rootCertificateId}   getRootCert

            AddHandler(
                HTTPMethod.GET,
                Route("rootCerts/{rootCertificateId}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response))
                        return response;

                    if (!TryParseURLParameter<RootCertificate_Id>(request,
                                                                  "rootCertificateId",
                                                                  RootCertificate_Id.TryParse,
                                                                  "root certificate identification",
                                                                  out var rootCertificateId,
                                                                  out response))
                    {
                        return response;
                    }

                    var rootCertificate = await Store.Get(rootCertificateId);

                    return rootCertificate is null

                               ? Refuse(request,
                                        HTTPStatusCode.NotFound,
                                        $"Root certificate with the given ID is not found")

                               : Respond(request,
                                         HTTPStatusCode.OK,
                                         RCPEnvelope.WrapOne(rootCertificate));

                }
            );

            #endregion

            #region DELETE  ~/v1/root/rootCerts/{rootCertificateId}   deleteRootCa

            AddHandler(
                HTTPMethod.DELETE,
                Route("rootCerts/{rootCertificateId}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.Admin))
                        return response;

                    if (!TryParseURLParameter<RootCertificate_Id>(request,
                                                                  "rootCertificateId",
                                                                  RootCertificate_Id.TryParse,
                                                                  "root certificate identification",
                                                                  out var rootCertificateId,
                                                                  out response))
                    {
                        return response;
                    }

                    // Removing a trust anchor leaves everything that chained to it in place:
                    // the specification is explicit that dependent provisioning certificates
                    // and contracts must not be cascade-deleted automatically.
                    var removed = await Store.Remove(rootCertificateId);

                    return removed is null

                               ? Refuse(request,
                                        HTTPStatusCode.NotFound,
                                        $"Root certificate with the given ID is not found")

                               : Respond(request,
                                         HTTPStatusCode.OK);

                }
            );

            #endregion

            #region GET     ~/v1/root/rootCerts                       getAllRootCerts

            AddHandler(
                HTTPMethod.GET,
                Route("rootCerts"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response))
                        return response;

                    #region Parse the optional rootType filter

                    RootCertificateType? rootType = null;

                    var rootTypeText = request.QueryString.GetString("rootType");

                    if (rootTypeText.IsNotNullOrEmpty())
                    {

                        // The filter is documented lowercase and the stored value is uppercase;
                        // the vocabulary parses either way, which is the whole point of it.
                        if (!RootCertificateType.TryParse(rootTypeText, out var parsed))
                            return Refuse(request,
                                          HTTPStatusCode.BadRequest,
                                          $"'{rootTypeText}' is not a valid root certificate type!");

                        rootType = parsed;

                    }

                    #endregion

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   RCPEnvelope.WrapMany(await Store.GetAll(rootType)));

                }
            );

            #endregion

            #region PUT     ~/v1/root/rootCerts                       saveRootCa

            AddHandler(
                HTTPMethod.PUT,
                Route("rootCerts"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.Admin))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!AddRootCertificateRequest.TryParse(json, out var addRequest, out var errorResponse))
                        return Refuse(request,
                                      HTTPStatusCode.BadRequest,
                                      errorResponse);

                    #region The certificate has to be one

                    if (!addRequest.Certificate.IsCertificateAuthority)
                        return Refuse(request,
                                      HTTPStatusCode.BadRequest,
                                      "The given certificate is not a certification authority!");

                    if (!addRequest.Certificate.IsValidAt(Timestamp.Now))
                        return Refuse(request,
                                      HTTPStatusCode.BadRequest,
                                      $"The given certificate is not valid at this time " +
                                      $"({addRequest.Certificate.NotBefore:yyyy-MM-dd} to {addRequest.Certificate.NotAfter:yyyy-MM-dd})!");

                    #endregion

                    var stored = await Store.Add(
                                     new RootCertificate(
                                         addRequest.RootType,
                                         addRequest.Certificate
                                     )
                                 );

                    // The specification documents no body here. Returning the stored entry is
                    // the only way a caller learns the identification it was given without
                    // listing the whole pool afterwards.
                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   RCPEnvelope.WrapOne(stored));

                }
            );

            #endregion

            #region GET     ~/v1/root/ctl                             GetCertificateTrustList

            AddHandler(
                HTTPMethod.GET,
                Route("ctl"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response))
                        return response;

                    // OPCP 1.0.0 leaves the content of the trust list "still to be aligned by
                    // stakeholders". Answering with the anchors themselves and no signature is
                    // the honest reading: there is nothing yet to sign them into.
                    var rootCertificates = await Store.GetAll();

                    return Respond(request,
                                   HTTPStatusCode.OK,
                                   new JObject(
                                       new JProperty("timeStamp",  Timestamp.Now.ToISO8601(false)),
                                       new JProperty("CTL",        RCPEnvelope.WrapMany(rootCertificates))
                                   ));

                }
            );

            #endregion

        }

        #endregion

    }

}
