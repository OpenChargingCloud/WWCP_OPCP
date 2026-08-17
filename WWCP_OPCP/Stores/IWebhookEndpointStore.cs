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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Where a webhook service keeps the endpoints partners registered.
    /// </summary>
    public interface IWebhookEndpointStore
    {

        /// <summary>
        /// Register an endpoint, or replace one of the same identification.
        /// </summary>
        /// <param name="Endpoint">An endpoint.</param>
        Task<WebhookEndpoint> Add(WebhookEndpoint Endpoint);

        /// <summary>
        /// Return the endpoint with the given identification, or null.
        /// </summary>
        /// <param name="Id">An endpoint identification.</param>
        Task<WebhookEndpoint?> Get(Webhook_Id Id);

        /// <summary>
        /// Every registered endpoint, optionally only those one partner registered.
        /// </summary>
        /// <param name="UserName">An optional partner to filter by.</param>
        Task<IEnumerable<WebhookEndpoint>> GetAll(String? UserName = null);

        /// <summary>
        /// Remove the endpoint with the given identification.
        /// </summary>
        /// <param name="Id">An endpoint identification.</param>
        /// <returns>What was removed, or null when there was nothing.</returns>
        Task<WebhookEndpoint?> Remove(Webhook_Id Id);

    }


    /// <summary>
    /// A webhook service that keeps its endpoints in memory.
    /// </summary>
    public class InMemoryWebhookEndpointStore : IWebhookEndpointStore
    {

        #region Data

        private readonly ConcurrentDictionary<Webhook_Id, WebhookEndpoint> endpoints = [];

        #endregion

        #region Properties

        /// <summary>
        /// How many endpoints are registered.
        /// </summary>
        public Int32 Count
            => endpoints.Count;

        #endregion


        #region Add   (Endpoint)

        /// <summary>
        /// Register an endpoint, or replace one of the same identification.
        /// </summary>
        /// <param name="Endpoint">An endpoint.</param>
        public Task<WebhookEndpoint> Add(WebhookEndpoint Endpoint)
        {

            endpoints[Endpoint.Id] = Endpoint;

            return Task.FromResult(Endpoint);

        }

        #endregion

        #region Get   (Id)

        /// <summary>
        /// Return the endpoint with the given identification, or null.
        /// </summary>
        /// <param name="Id">An endpoint identification.</param>
        public Task<WebhookEndpoint?> Get(Webhook_Id Id)

            => Task.FromResult(
                   endpoints.TryGetValue(Id, out var endpoint)
                       ? endpoint
                       : null
               );

        #endregion

        #region GetAll(UserName = null)

        /// <summary>
        /// Every registered endpoint, optionally only those one partner registered.
        /// </summary>
        /// <param name="UserName">An optional partner to filter by.</param>
        public Task<IEnumerable<WebhookEndpoint>> GetAll(String? UserName = null)

            => Task.FromResult<IEnumerable<WebhookEndpoint>>(
                   [.. endpoints.Values.
                           Where  (endpoint => UserName.IsNullOrEmpty() ||
                                               String.Equals(endpoint.UserName, UserName, StringComparison.OrdinalIgnoreCase)).
                           OrderBy(endpoint => endpoint.Created)]
               );

        #endregion

        #region Remove(Id)

        /// <summary>
        /// Remove the endpoint with the given identification.
        /// </summary>
        /// <param name="Id">An endpoint identification.</param>
        public Task<WebhookEndpoint?> Remove(Webhook_Id Id)

            => Task.FromResult(
                   endpoints.TryRemove(Id, out var endpoint)
                       ? endpoint
                       : null
               );

        #endregion

    }

}
