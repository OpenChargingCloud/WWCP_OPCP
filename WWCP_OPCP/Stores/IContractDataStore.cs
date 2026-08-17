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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Where a Contract Certificate Pool keeps the contracts waiting to be installed.
    /// </summary>
    public interface IContractDataStore
    {

        /// <summary>
        /// Store a contract, replacing whatever was there under the same EMAID.
        /// </summary>
        /// <param name="ContractData">Signed contract data.</param>
        Task<SignedContractData> Add(SignedContractData ContractData);

        /// <summary>
        /// Return the contract with the given EMAID, or null.
        /// </summary>
        /// <param name="EMAId">A contract.</param>
        Task<SignedContractData?> Get(EMA_Id EMAId);

        /// <summary>
        /// Return every contract belonging to the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        Task<IEnumerable<SignedContractData>> GetByVehicle(PCID PCID);

        /// <summary>
        /// Return the contract to install when a vehicle expresses no preference, or null.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        Task<SignedContractData?> GetDefault(PCID PCID);

        /// <summary>
        /// Make one of a vehicle's contracts the one to install by default.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        /// <param name="EMAId">One of its contracts.</param>
        /// <returns>False when the vehicle has no such contract.</returns>
        Task<Boolean> SetDefault(PCID PCID, EMA_Id EMAId);

        /// <summary>
        /// Remove the contract with the given EMAID.
        /// </summary>
        /// <param name="EMAId">A contract.</param>
        /// <returns>What was removed, or null when there was nothing.</returns>
        Task<SignedContractData?> Remove(EMA_Id EMAId);

        /// <summary>
        /// Remove every contract belonging to the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        /// <returns>What was removed.</returns>
        Task<IEnumerable<SignedContractData>> RemoveByVehicle(PCID PCID);

    }


    /// <summary>
    /// A Contract Certificate Pool that keeps its contracts in memory.
    /// </summary>
    /// <remarks>
    /// The default-contract rules are the specification's, and the second one is easy to get
    /// wrong by being helpful: the first contract stored for a vehicle becomes its default, and
    /// when the default is deleted <b>no new default is chosen</b>. Picking one would mean the
    /// pool silently deciding which contract a car charges under - so instead the manufacturer is
    /// told, and decides.
    /// </remarks>
    public class InMemoryContractDataStore : IContractDataStore
    {

        #region Data

        private readonly ConcurrentDictionary<EMA_Id, SignedContractData> contracts = [];

        #endregion

        #region Properties

        /// <summary>
        /// How many contracts the pool holds.
        /// </summary>
        public Int32 Count
            => contracts.Count;

        #endregion


        #region Add           (ContractData)

        /// <summary>
        /// Store a contract, replacing whatever was there under the same EMAID.
        /// </summary>
        /// <param name="ContractData">Signed contract data.</param>
        public Task<SignedContractData> Add(SignedContractData ContractData)
        {

            contracts.TryGetValue(ContractData.EMAId, out var previous);

            // The first contract a vehicle gets is its default. A replacement keeps whatever
            // the one it replaced was.
            var isDefault = previous?.IsDefault
                                ?? !contracts.Values.Any(contract => contract.PCID == ContractData.PCID);

            var stored    = ContractData.With(IsDefault: isDefault);

            contracts[ContractData.EMAId] = stored;

            return Task.FromResult(stored);

        }

        #endregion

        #region Get           (EMAId)

        /// <summary>
        /// Return the contract with the given EMAID, or null.
        /// </summary>
        /// <param name="EMAId">A contract.</param>
        public Task<SignedContractData?> Get(EMA_Id EMAId)

            => Task.FromResult(
                   contracts.TryGetValue(EMAId, out var contract)
                       ? contract
                       : null
               );

        #endregion

        #region GetByVehicle  (PCID)

        /// <summary>
        /// Return every contract belonging to the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<IEnumerable<SignedContractData>> GetByVehicle(PCID PCID)

            => Task.FromResult<IEnumerable<SignedContractData>>(
                   [.. contracts.Values.
                           Where  (contract => contract.PCID == PCID).
                           OrderBy(contract => contract.EMAId.ToString())]
               );

        #endregion

        #region GetDefault    (PCID)

        /// <summary>
        /// Return the contract to install when a vehicle expresses no preference, or null.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<SignedContractData?> GetDefault(PCID PCID)

            => Task.FromResult(
                   contracts.Values.FirstOrDefault(contract => contract.PCID == PCID && contract.IsDefault)
               );

        #endregion

        #region SetDefault    (PCID, EMAId)

        /// <summary>
        /// Make one of a vehicle's contracts the one to install by default.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        /// <param name="EMAId">One of its contracts.</param>
        public Task<Boolean> SetDefault(PCID PCID, EMA_Id EMAId)
        {

            if (!contracts.TryGetValue(EMAId, out var contract) || contract.PCID != PCID)
                return Task.FromResult(false);

            foreach (var other in contracts.Values.Where(other => other.PCID == PCID && other.IsDefault))
                contracts[other.EMAId] = other.With(IsDefault: false);

            contracts[EMAId] = contract.With(IsDefault: true);

            return Task.FromResult(true);

        }

        #endregion

        #region Remove        (EMAId)

        /// <summary>
        /// Remove the contract with the given EMAID.
        /// </summary>
        /// <param name="EMAId">A contract.</param>
        /// <remarks>
        /// Removing the default leaves the vehicle without one. That is the specification's rule,
        /// and the manufacturer is notified rather than the pool quietly promoting another.
        /// </remarks>
        public Task<SignedContractData?> Remove(EMA_Id EMAId)

            => Task.FromResult(
                   contracts.TryRemove(EMAId, out var contract)
                       ? contract
                       : null
               );

        #endregion

        #region RemoveByVehicle(PCID)

        /// <summary>
        /// Remove every contract belonging to the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<IEnumerable<SignedContractData>> RemoveByVehicle(PCID PCID)
        {

            var removed = new List<SignedContractData>();

            foreach (var contract in contracts.Values.Where(contract => contract.PCID == PCID).ToArray())
                if (contracts.TryRemove(contract.EMAId, out var gone))
                    removed.Add(gone);

            return Task.FromResult<IEnumerable<SignedContractData>>(removed);

        }

        #endregion

    }

}
