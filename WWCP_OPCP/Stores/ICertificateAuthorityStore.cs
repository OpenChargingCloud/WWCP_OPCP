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
    /// Where a V2G PKI service keeps the authorities it issues from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two things pick one out: which authority - the charge point operator's, the mobility
    /// operator's, a vehicle manufacturer's - and on which curve. A real V2G PKI runs the same
    /// hierarchy several times over, once per algorithm, because a vehicle that only speaks
    /// secp256r1 cannot verify a chain signed on ed448; the enrollment interface says as much by
    /// putting the algorithm in the path of its CA distribution.
    /// </para>
    /// <para>
    /// These are held as <see cref="IssuedCertificate"/>: issuing needs the private key, and
    /// publishing the chain needs the path above it. In a real deployment the key is in an HSM and
    /// this store holds a handle to it.
    /// </para>
    /// </remarks>
    public interface ICertificateAuthorityStore
    {

        /// <summary>
        /// Register an issuing authority, replacing one already held for the same identification
        /// and curve.
        /// </summary>
        /// <param name="CA">Which authority this is.</param>
        /// <param name="Authority">The issuing certificate, together with the path above it.</param>
        Task<IssuedCertificate> Add(CA_Id CA, IssuedCertificate Authority);

        /// <summary>
        /// The authority that issues for the given identification on the given curve.
        /// </summary>
        /// <param name="CA">Which authority.</param>
        /// <param name="Algorithm">
        /// Which curve. Nothing given means whichever this service registered first for that
        /// authority - the one an enrollment interface calls its default.
        /// </param>
        /// <returns>The authority, or null when this service operates none such.</returns>
        Task<IssuedCertificate?> Get(CA_Id CA, SignatureAlgorithm? Algorithm = null);

        /// <summary>
        /// Every authority this service operates.
        /// </summary>
        Task<IEnumerable<CA_Id>> GetAll();

    }


    /// <summary>
    /// A V2G PKI service that keeps its authorities in memory.
    /// </summary>
    public class InMemoryCertificateAuthorityStore : ICertificateAuthorityStore
    {

        #region Data

        private readonly ConcurrentDictionary<CA_Id, List<IssuedCertificate>> authorities = [];

        #endregion

        #region Properties

        /// <summary>
        /// How many authorities this service operates, counting one hierarchy per curve.
        /// </summary>
        public Int32 Count
            => authorities.Values.Sum(list => list.Count);

        #endregion


        #region Add   (CA, Authority)

        /// <summary>
        /// Register an issuing authority, replacing one already held for the same identification
        /// and curve.
        /// </summary>
        /// <param name="CA">Which authority this is.</param>
        /// <param name="Authority">The issuing certificate, together with the path above it.</param>
        public Task<IssuedCertificate> Add(CA_Id              CA,
                                           IssuedCertificate  Authority)
        {

            var list = authorities.GetOrAdd(CA, _ => []);

            lock (list)
            {

                var algorithm = Authority.Certificate.SignatureAlgorithm;

                list.RemoveAll(authority => authority.Certificate.SignatureAlgorithm == algorithm);

                list.Add(Authority);

            }

            return Task.FromResult(Authority);

        }

        #endregion

        #region Get   (CA, Algorithm = null)

        /// <summary>
        /// The authority that issues for the given identification on the given curve.
        /// </summary>
        /// <param name="CA">Which authority.</param>
        /// <param name="Algorithm">Which curve, or the first one registered.</param>
        public Task<IssuedCertificate?> Get(CA_Id                CA,
                                            SignatureAlgorithm?  Algorithm   = null)
        {

            if (!authorities.TryGetValue(CA, out var list))
                return Task.FromResult<IssuedCertificate?>(null);

            lock (list)
            {

                if (!Algorithm.HasValue)
                    return Task.FromResult(list.FirstOrDefault());

                return Task.FromResult(
                           list.FirstOrDefault(authority => authority.Certificate.SignatureAlgorithm == Algorithm.Value)
                       );

            }

        }

        #endregion

        #region GetAll()

        /// <summary>
        /// Every authority this service operates.
        /// </summary>
        public Task<IEnumerable<CA_Id>> GetAll()

            => Task.FromResult<IEnumerable<CA_Id>>(
                   [.. authorities.Keys.OrderBy(ca => ca.ToString())]
               );

        #endregion

    }

}
