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
    /// Where a Root Certificate Pool keeps its trust anchors.
    ///
    /// The store is an abstraction so that the pool's HTTP interface and the question of where
    /// its state lives stay separable - the in-memory implementation below is what the tests and
    /// a development ecosystem use, and a database-backed one changes nothing above it.
    /// </summary>
    public interface IRootCertificateStore
    {

        /// <summary>
        /// Admit a root certificate and return it under the identification it was given.
        /// </summary>
        /// <param name="RootCertificate">A root certificate without an identification.</param>
        Task<RootCertificate> Add(RootCertificate RootCertificate);

        /// <summary>
        /// Return the root certificate with the given identification, or null.
        /// </summary>
        /// <param name="Id">A root certificate identification.</param>
        Task<RootCertificate?> Get(RootCertificate_Id Id);

        /// <summary>
        /// Return all root certificates, optionally of one trust domain only.
        /// </summary>
        /// <param name="RootType">An optional trust domain to filter by.</param>
        Task<IEnumerable<RootCertificate>> GetAll(RootCertificateType? RootType = null);

        /// <summary>
        /// Remove the root certificate with the given identification.
        /// </summary>
        /// <param name="Id">A root certificate identification.</param>
        /// <returns>The removed root certificate, or null when there was none.</returns>
        Task<RootCertificate?> Remove(RootCertificate_Id Id);

    }


    /// <summary>
    /// A Root Certificate Pool that keeps its trust anchors in memory.
    /// </summary>
    /// <remarks>
    /// Admitting a certificate that is already in the pool returns the existing entry rather than
    /// creating a second one. The specification does not say to do this, but a pool is a set of
    /// trust anchors: two entries for one certificate would give participants two answers to
    /// "which roots do I trust", differing only in a UUID.
    /// </remarks>
    public class InMemoryRootCertificateStore : IRootCertificateStore
    {

        #region Data

        private readonly ConcurrentDictionary<RootCertificate_Id, RootCertificate> rootCertificates = [];

        #endregion

        #region Properties

        /// <summary>
        /// How many root certificates the pool holds.
        /// </summary>
        public Int32 Count
            => rootCertificates.Count;

        #endregion


        #region Add   (RootCertificate)

        /// <summary>
        /// Admit a root certificate and return it under the identification it was given.
        /// </summary>
        /// <param name="RootCertificate">A root certificate without an identification.</param>
        public Task<RootCertificate> Add(RootCertificate RootCertificate)
        {

            var existing = rootCertificates.Values.FirstOrDefault(
                               stored => stored.Certificate.Equals(RootCertificate.Certificate) &&
                                         stored.RootType.   Equals(RootCertificate.RootType)
                           );

            if (existing is not null)
                return Task.FromResult(existing);

            var stored2 = RootCertificate.WithId(RootCertificate_Id.NewRandom());

            rootCertificates.TryAdd(stored2.Id!.Value, stored2);

            return Task.FromResult(stored2);

        }

        #endregion

        #region Get   (Id)

        /// <summary>
        /// Return the root certificate with the given identification, or null.
        /// </summary>
        /// <param name="Id">A root certificate identification.</param>
        public Task<RootCertificate?> Get(RootCertificate_Id Id)

            => Task.FromResult(
                   rootCertificates.TryGetValue(Id, out var rootCertificate)
                       ? rootCertificate
                       : null
               );

        #endregion

        #region GetAll(RootType = null)

        /// <summary>
        /// Return all root certificates, optionally of one trust domain only.
        /// </summary>
        /// <param name="RootType">An optional trust domain to filter by.</param>
        public Task<IEnumerable<RootCertificate>> GetAll(RootCertificateType? RootType = null)

            => Task.FromResult<IEnumerable<RootCertificate>>(
                   [.. rootCertificates.Values.
                           Where  (rootCertificate => !RootType.HasValue || rootCertificate.RootType == RootType.Value).
                           OrderBy(rootCertificate => rootCertificate.CommonName)]
               );

        #endregion

        #region Remove(Id)

        /// <summary>
        /// Remove the root certificate with the given identification.
        /// </summary>
        /// <param name="Id">A root certificate identification.</param>
        /// <returns>The removed root certificate, or null when there was none.</returns>
        public Task<RootCertificate?> Remove(RootCertificate_Id Id)

            => Task.FromResult(
                   rootCertificates.TryRemove(Id, out var rootCertificate)
                       ? rootCertificate
                       : null
               );

        #endregion

    }

}
