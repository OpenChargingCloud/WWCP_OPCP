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
    /// Where partners say what they want to be told about.
    ///
    /// Everything the ecosystem does happens to somebody else's asset: a root a charge point
    /// operator has to push to its stations, a vehicle whose contracts just went away, a contract
    /// that finally reached a car. This is where a partner registers an endpoint for that news,
    /// and where the ecosystem records what that partner is allowed to hear.
    /// </summary>
    public class Webhook_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the webhook service is mounted.
        /// </summary>
        public static readonly HTTPPath DefaultRootPath = HTTPPath.Parse("/v1/webhook/");

        #endregion

        #region Properties

        /// <summary>
        /// What sends the events, and where the registered endpoints live.
        /// </summary>
        public WebhookDeliveryService  Delivery     { get; }

        /// <summary>
        /// Where the registered endpoints live.
        /// </summary>
        public IWebhookEndpointStore   Endpoints
            => Delivery.Endpoints;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook service.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Delivery">An optional delivery service, otherwise one with an in-memory store.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public Webhook_HTTPAPI(HTTPServer               HTTPServer,
                               WebhookDeliveryService?  Delivery               = null,
                               IAccessTokenValidator?   AccessTokenValidator   = null,
                               HTTPPath?                RootPath               = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP Webhook Service"))

        {

            this.Delivery = Delivery ?? new WebhookDeliveryService();

            RegisterURLTemplates();

        }

        #endregion


        #region AttachTo(RootCertificatePool | ProvisioningCertificatePool | ContractCertificatePool)

        /// <summary>
        /// Follow what happens in a Root Certificate Pool.
        /// </summary>
        /// <param name="RootCertificatePool">The pool to follow.</param>
        public void AttachTo(RCP_HTTPAPI RootCertificatePool)
        {

            RootCertificatePool.OnRootCertificateAdded += rootCertificate => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForRootCertificate(WebhookEventType.RootCertificateAdded, rootCertificate)
                );
                return Task.CompletedTask;
            };

            RootCertificatePool.OnRootCertificateRemoved += rootCertificate => {
                // The pool has one way to lose a root and the specification has two words for it.
                // A root that is still valid was taken away on purpose; one that is not simply
                // reached the end of what it was issued for.
                Delivery.PublishInBackground(
                    WebhookEvent.ForRootCertificate(
                        rootCertificate.ValidTo <= DateTimeOffset.UtcNow
                            ? WebhookEventType.RootCertificateExpired
                            : WebhookEventType.RootCertificateRevoked,
                        rootCertificate
                    )
                );
                return Task.CompletedTask;
            };

        }

        /// <summary>
        /// Follow what happens in a Provisioning Certificate Pool.
        /// </summary>
        /// <param name="ProvisioningCertificatePool">The pool to follow.</param>
        public void AttachTo(PCP_HTTPAPI ProvisioningCertificatePool)
        {

            ProvisioningCertificatePool.OnProvisioningCertificateDeleted += (pcid, certificate) => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForVehicle(WebhookEventType.ProvisioningCertificateDeleted, pcid)
                );
                return Task.CompletedTask;
            };

            ProvisioningCertificatePool.OnVehicleKeyChanged += (pcid, certificate) => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForVehicle(WebhookEventType.ProvisioningCertificateUpdated, pcid)
                );
                return Task.CompletedTask;
            };

        }

        /// <summary>
        /// Follow what happens in a Contract Certificate Pool.
        /// </summary>
        /// <param name="ContractCertificatePool">The pool to follow.</param>
        /// <remarks>
        /// These are the events a vehicle manufacturer's backend actually acts on: a contract
        /// appearing for one of its cars, one being replaced, one going away, and one finally
        /// reaching the car it was written for.
        /// </remarks>
        public void AttachTo(CCP_HTTPAPI ContractCertificatePool)
        {

            ContractCertificatePool.OnContractStored += (contract, replaced) => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForContract(
                        replaced
                            ? WebhookEventType.ContractUpdated
                            : WebhookEventType.ContractCreated,
                        contract.EMAId,
                        contract.PCID,
                        contract.ContractCertificate,
                        contract.CpsV2GRootCertificateFingerprint,
                        XSDMsgDefNamespace: contract.XSDMsgDefNamespace
                    )
                );
                return Task.CompletedTask;
            };

            ContractCertificatePool.OnContractRemoved += contract => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForContract(
                        WebhookEventType.ContractDeleted,
                        contract.EMAId,
                        contract.PCID,
                        XSDMsgDefNamespace: contract.XSDMsgDefNamespace
                    )
                );
                return Task.CompletedTask;
            };

            ContractCertificatePool.OnContractDelivered += contract => {
                Delivery.PublishInBackground(
                    WebhookEvent.ForContract(
                        WebhookEventType.ContractDeliveredToOEM,
                        contract.EMAId,
                        contract.PCID,
                        contract.ContractCertificate,
                        contract.CpsV2GRootCertificateFingerprint,
                        XSDMsgDefNamespace: contract.XSDMsgDefNamespace
                    )
                );
                return Task.CompletedTask;
            };

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region POST    ~/v1/webhook/endpoints          create-webhook-endpoint

            AddHandler(
                HTTPMethod.POST,
                Route("endpoints"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    // The interface document declares no security for any of these five
                    // operations. That is an omission rather than an intention: an endpoint
                    // registration decides who is told about somebody's cars, so it is
                    // authenticated like everything else here.
                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.CPO, OPCPRole.CPS,
                                                                        OPCPRole.MO,  OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                        return response;

                    if (!TryParseJSONBody(request, out var json, out response))
                        return response;

                    if (!WebhookEndpoint.TryParse(json, out var endpoint, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    if (!endpoint.EnabledEvents.Any())
                        return Refuse(request,
                                      HTTPStatusCode.BadRequest,
                                      "enabledEvents : at least one event has to be named!");

                    // What the partner may hear about is not the partner's to state: it comes
                    // from the token, along with a fresh secret and an identification of ours.
                    var stored = await Endpoints.Add(
                                           endpoint.With(
                                               Id:           Webhook_Id.NewRandom(),
                                               Created:      Timestamp.Now,
                                               Secret:       WebhookEndpoint.NewSecret(),
                                               ProviderIds:  tokenInfo.ProviderIds,
                                               WMIs:         tokenInfo.WMIs,
                                               UserRole:     tokenInfo.Roles.FirstOrDefault(),
                                               UserName:     NameOf(tokenInfo)
                                           )
                                       );

                    return Respond(request, HTTPStatusCode.Created, stored.ToJSON());

                }
            );

            #endregion

            #region GET     ~/v1/webhook/endpoints          get-webhook-endpoints

            AddHandler(
                HTTPMethod.GET,
                Route("endpoints"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    if (!TryAuthenticate(request, out var tokenInfo, out var response))
                        return response;

                    if (!TryAuthorize(request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.CPO, OPCPRole.CPS,
                                                                        OPCPRole.MO,  OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                        return response;

                    // "Returns users all webhook endpoints" - one partner's own, and not the
                    // ecosystem's, whose URLs and secrets are nobody else's business.
                    var endpoints = await Endpoints.GetAll(NameOf(tokenInfo));

                    return Respond(
                               request,
                               HTTPStatusCode.OK,
                               new JObject(
                                   new JProperty("endpoints",
                                                 new JArray(endpoints.Select(endpoint => endpoint.ToJSON())))
                               )
                           );

                }
            );

            #endregion

            #region GET     ~/v1/webhook/endpoints/{id}     get-webhook-endpoint

            AddHandler(
                HTTPMethod.GET,
                Route("endpoints/{id}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    var (endpoint, refusal) = await Find(request);

                    return endpoint is not null
                               ? Respond(request, HTTPStatusCode.OK, endpoint.ToJSON())
                               : refusal!;

                }
            );

            #endregion

            #region PUT     ~/v1/webhook/endpoints/{id}     update-webhook-endpoint

            AddHandler(
                HTTPMethod.PUT,
                Route("endpoints/{id}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    var (existing, refusal) = await Find(request);

                    if (existing is null)
                        return refusal!;

                    if (!TryParseJSONBody(request, out var json, out var response))
                        return response;

                    if (!WebhookEndpoint.TryParse(json, out var update, out var errorResponse))
                        return Refuse(request, HTTPStatusCode.BadRequest, errorResponse);

                    // The identification, the secret, who owns it and what it may hear about
                    // stay what they were: an update edits the subscription, not the subscriber.
                    var stored = await Endpoints.Add(
                                           update.With(
                                               Id:           existing.Id,
                                               Created:      existing.Created,
                                               Secret:       existing.Secret,
                                               ProviderIds:  existing.ProviderIds,
                                               WMIs:         existing.WMIs,
                                               UserRole:     existing.UserRole,
                                               UserName:     existing.UserName
                                           )
                                       );

                    return Respond(request, HTTPStatusCode.OK, stored.ToJSON());

                }
            );

            #endregion

            #region DELETE  ~/v1/webhook/endpoints/{id}     delete-webhook-endpoint

            AddHandler(
                HTTPMethod.DELETE,
                Route("endpoints/{id}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: async request => {

                    var (endpoint, refusal) = await Find(request);

                    if (endpoint is null)
                        return refusal!;

                    await Endpoints.Remove(endpoint.Id);

                    return Respond(request, HTTPStatusCode.OK);

                }
            );

            #endregion

        }

        #endregion


        #region (private) Find  (Request)

        /// <summary>
        /// Read the endpoint one request is about, and check that it belongs to whoever is asking.
        /// </summary>
        /// <returns>The endpoint, or the refusal to send back instead.</returns>
        /// <remarks>
        /// An endpoint somebody else registered is answered as not found rather than as
        /// forbidden. Which identifications exist is not something a partner needs to learn by
        /// asking for them one at a time.
        /// </remarks>
        private async Task<(WebhookEndpoint? Endpoint, HTTPResponse? Response)> Find(HTTPRequest Request)
        {

            if (!TryAuthenticate(Request, out var tokenInfo, out var response))
                return (null, response);

            if (!TryAuthorize(Request, tokenInfo, out response, OPCPRole.OEM, OPCPRole.CPO, OPCPRole.CPS,
                                                                OPCPRole.MO,  OPCPRole.MO_ExternalPKI, OPCPRole.MO_V2GPKI))
                return (null, response);

            if (!TryParseURLParameter<Webhook_Id>(Request, "id", Webhook_Id.TryParse,
                                                  "webhook endpoint identification", out var id, out response))
                return (null, response);

            var endpoint = await Endpoints.Get(id);

            if (endpoint is null ||
                (AccessTokenValidator is not null &&
                 !String.Equals(endpoint.UserName, NameOf(tokenInfo), StringComparison.OrdinalIgnoreCase)))
            {
                return (null, Refuse(Request,
                                     HTTPStatusCode.NotFound,
                                     $"No webhook endpoint '{id}' was found."));
            }

            return (endpoint, null);

        }

        #endregion

        #region (private, static) NameOf(TokenInfo)

        /// <summary>
        /// Who a token says its holder is.
        /// </summary>
        private static String NameOf(OPCPTokenInfo TokenInfo)

            => TokenInfo.Subject.IsNotNullOrEmpty()
                   ? TokenInfo.Subject!
                   : "anonymous";

        #endregion

    }

}
