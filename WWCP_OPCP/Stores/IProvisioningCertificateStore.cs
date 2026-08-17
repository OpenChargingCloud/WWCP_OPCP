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
    /// What happened when a provisioning certificate was published.
    /// </summary>
    /// <param name="Certificate">The chain as the pool now holds it.</param>
    /// <param name="Replaced">Whether it took the place of one already there.</param>
    /// <param name="KeyChanged">
    /// Whether the vehicle's key changed with it. This is the workshop case: a vehicle whose key
    /// pair was replaced cannot use any contract issued against the old one, and the specification
    /// has the pool delete them rather than leave them to fail at a charging station.
    /// </param>
    public sealed record ProvisioningCertificateStored(ProvisioningCertificate  Certificate,
                                                       Boolean                  Replaced,
                                                       Boolean                  KeyChanged);


    /// <summary>
    /// Where a Provisioning Certificate Pool keeps the certificates vehicles were born with.
    /// </summary>
    public interface IProvisioningCertificateStore
    {

        /// <summary>
        /// Publish a provisioning certificate, replacing whatever was there for the same vehicle.
        /// </summary>
        /// <param name="Certificate">A validated provisioning certificate chain.</param>
        Task<ProvisioningCertificateStored> Add(ProvisioningCertificate Certificate);

        /// <summary>
        /// Return the provisioning certificate of the given vehicle, or null.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        Task<ProvisioningCertificate?> Get(PCID PCID);

        /// <summary>
        /// Whether the pool holds a certificate for the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        Task<Boolean> Contains(PCID PCID);

        /// <summary>
        /// Depublish the provisioning certificate of the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        /// <returns>What was removed, or null when there was nothing.</returns>
        Task<ProvisioningCertificate?> Remove(PCID PCID);

        /// <summary>
        /// All vehicles the pool holds a certificate for, optionally of one manufacturer only.
        /// </summary>
        /// <param name="WMI">An optional manufacturer to filter by.</param>
        Task<IEnumerable<PCID>> GetAll(WMI? WMI = null);

    }


    /// <summary>
    /// A Provisioning Certificate Pool that keeps its vehicles in memory.
    /// </summary>
    public class InMemoryProvisioningCertificateStore : IProvisioningCertificateStore
    {

        #region Data

        private readonly ConcurrentDictionary<PCID, ProvisioningCertificate> certificates = [];

        #endregion

        #region Properties

        /// <summary>
        /// How many vehicles the pool holds a certificate for.
        /// </summary>
        public Int32 Count
            => certificates.Count;

        #endregion


        #region Add     (Certificate)

        /// <summary>
        /// Publish a provisioning certificate, replacing whatever was there for the same vehicle.
        /// </summary>
        /// <param name="Certificate">A validated provisioning certificate chain.</param>
        public Task<ProvisioningCertificateStored> Add(ProvisioningCertificate Certificate)
        {

            var pcid = Certificate.PCID
                           ?? throw new ArgumentException("The given certificate does not name a vehicle!",
                                                          nameof(Certificate));

            certificates.TryGetValue(pcid, out var previous);

            certificates[pcid] = Certificate;

            return Task.FromResult(
                       new ProvisioningCertificateStored(
                           Certificate,
                           previous is not null,
                           previous is not null && !previous.HasSameKeyAs(Certificate)
                       )
                   );

        }

        #endregion

        #region Get     (PCID)

        /// <summary>
        /// Return the provisioning certificate of the given vehicle, or null.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<ProvisioningCertificate?> Get(PCID PCID)

            => Task.FromResult(
                   certificates.TryGetValue(PCID, out var certificate)
                       ? certificate
                       : null
               );

        #endregion

        #region Contains(PCID)

        /// <summary>
        /// Whether the pool holds a certificate for the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<Boolean> Contains(PCID PCID)

            => Task.FromResult(certificates.ContainsKey(PCID));

        #endregion

        #region Remove  (PCID)

        /// <summary>
        /// Depublish the provisioning certificate of the given vehicle.
        /// </summary>
        /// <param name="PCID">A vehicle.</param>
        public Task<ProvisioningCertificate?> Remove(PCID PCID)

            => Task.FromResult(
                   certificates.TryRemove(PCID, out var certificate)
                       ? certificate
                       : null
               );

        #endregion

        #region GetAll  (WMI = null)

        /// <summary>
        /// All vehicles the pool holds a certificate for, optionally of one manufacturer only.
        /// </summary>
        /// <param name="WMI">An optional manufacturer to filter by.</param>
        public Task<IEnumerable<PCID>> GetAll(WMI? WMI = null)

            => Task.FromResult<IEnumerable<PCID>>(
                   [.. certificates.Keys.
                           Where  (pcid => !WMI.HasValue || pcid.WMI == WMI.Value).
                           OrderBy(pcid => pcid.ToString())]
               );

        #endregion

    }

}
