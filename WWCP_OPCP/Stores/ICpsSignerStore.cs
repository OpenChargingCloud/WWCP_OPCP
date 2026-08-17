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
    /// Where a Certificate Provisioning Service keeps the certificates it signs with.
    /// </summary>
    /// <remarks>
    /// These are held as <see cref="IssuedCertificate"/> and not as <see cref="CpsSigner"/>,
    /// because signing needs the private key and the published description has nowhere to put
    /// one. What an operator gets to see is derived from these on the way out.
    /// </remarks>
    public interface ICpsSignerStore
    {

        /// <summary>
        /// Register a signing certificate.
        /// </summary>
        /// <param name="Signer">A signing certificate, together with the path it was issued along.</param>
        Task<IssuedCertificate> Add(IssuedCertificate Signer);

        /// <summary>
        /// Every signing certificate this service offers.
        /// </summary>
        Task<IEnumerable<IssuedCertificate>> GetAll();

        /// <summary>
        /// The signing certificate anchored to the given V2G root.
        /// </summary>
        /// <param name="CpsV2GRootCertificateFingerprint">
        /// A V2G root. Nothing given means the service chooses, which is what the specification
        /// says it does when an operator expresses no preference.
        /// </param>
        /// <returns>The signer, or null when the service has none for that root.</returns>
        Task<IssuedCertificate?> Get(String? CpsV2GRootCertificateFingerprint = null);

    }


    /// <summary>
    /// A Certificate Provisioning Service that keeps its signing certificates in memory.
    /// </summary>
    /// <remarks>
    /// The keys are in this process, which is the one thing a real deployment does differently:
    /// there they live in an HSM and this store holds handles to them.
    /// </remarks>
    public class InMemoryCpsSignerStore : ICpsSignerStore
    {

        #region Data

        private readonly List<IssuedCertificate>  signers  = [];
        private readonly Lock                     padlock  = new ();

        #endregion

        #region Properties

        /// <summary>
        /// How many signing certificates the service offers.
        /// </summary>
        public Int32 Count
        {
            get
            {
                lock (padlock)
                {
                    return signers.Count;
                }
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new store of signing certificates.
        /// </summary>
        /// <param name="Signers">The signing certificates to start with. The first is the one
        /// used when an operator expresses no preference.</param>
        public InMemoryCpsSignerStore(params IssuedCertificate[] Signers)
        {
            this.signers.AddRange(Signers);
        }

        #endregion


        #region Add   (Signer)

        /// <summary>
        /// Register a signing certificate, replacing one already held for the same V2G root.
        /// </summary>
        /// <param name="Signer">A signing certificate.</param>
        public Task<IssuedCertificate> Add(IssuedCertificate Signer)
        {

            lock (padlock)
            {

                var root = Signer.Root.Certificate.SHA256Fingerprint;

                signers.RemoveAll(signer => signer.Root.Certificate.SHA256Fingerprint == root);

                signers.Add(Signer);

            }

            return Task.FromResult(Signer);

        }

        #endregion

        #region GetAll()

        /// <summary>
        /// Every signing certificate this service offers.
        /// </summary>
        public Task<IEnumerable<IssuedCertificate>> GetAll()
        {
            lock (padlock)
            {
                return Task.FromResult<IEnumerable<IssuedCertificate>>([.. signers]);
            }
        }

        #endregion

        #region Get   (CpsV2GRootCertificateFingerprint = null)

        /// <summary>
        /// The signing certificate anchored to the given V2G root, or the first one when no
        /// preference was expressed.
        /// </summary>
        /// <param name="CpsV2GRootCertificateFingerprint">An optional V2G root.</param>
        public Task<IssuedCertificate?> Get(String? CpsV2GRootCertificateFingerprint = null)
        {

            lock (padlock)
            {

                if (CpsV2GRootCertificateFingerprint.IsNullOrEmpty())
                    return Task.FromResult(signers.FirstOrDefault());

                return Task.FromResult(
                           signers.FirstOrDefault(signer => signer.Root.Certificate.SHA256Fingerprint.Equals(
                                                                CpsV2GRootCertificateFingerprint,
                                                                StringComparison.OrdinalIgnoreCase))
                       );

            }

        }

        #endregion

    }

}
