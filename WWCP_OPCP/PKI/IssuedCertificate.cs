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

using Org.BouncyCastle.Crypto;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A certificate together with the key it belongs to and the certificate that issued it.
    ///
    /// A certificate on its own cannot be used - signing needs its private key, and validating
    /// needs the path back to a root. Both are here, so that what a Plug&amp;Charge PKI produces
    /// stays usable rather than merely inspectable.
    /// </summary>
    public class IssuedCertificate
    {

        #region Properties

        /// <summary>
        /// The certificate.
        /// </summary>
        public PnCCertificate           Certificate    { get; }

        /// <summary>
        /// The key pair the certificate belongs to.
        /// </summary>
        public AsymmetricCipherKeyPair  KeyPair        { get; }

        /// <summary>
        /// What issued this certificate - null for a root, which issued itself.
        /// </summary>
        public IssuedCertificate?       Issuer         { get; }


        /// <summary>
        /// The private key.
        /// </summary>
        public AsymmetricKeyParameter   PrivateKey
            => KeyPair.Private;

        /// <summary>
        /// The public key.
        /// </summary>
        public AsymmetricKeyParameter   PublicKey
            => KeyPair.Public;

        /// <summary>
        /// The root this certificate chains up to - itself, for a root.
        /// </summary>
        public IssuedCertificate        Root
        {
            get
            {

                var current = this;

                while (current.Issuer is not null)
                    current = current.Issuer;

                return current;

            }
        }

        /// <summary>
        /// The whole path, this certificate first and its root last.
        /// </summary>
        public IEnumerable<PnCCertificate> Chain
        {
            get
            {

                var chain    = new List<PnCCertificate>();
                var current  = this;

                while (true)
                {

                    chain.Add(current.Certificate);

                    if (current.Issuer is null)
                        break;

                    current = current.Issuer;

                }

                return chain;

            }
        }

        /// <summary>
        /// The certificates between this one and its root, nearest first.
        ///
        /// This is what OPCP transports beside a leaf: the provisioning certificate pool asks for
        /// the sub-CAs and derives the root itself, because the root is something the recipient is
        /// supposed to already have.
        /// </summary>
        public IEnumerable<PnCCertificate> SubCAs
            => Chain.Skip(1).SkipLast(1);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new issued certificate.
        /// </summary>
        /// <param name="Certificate">The certificate.</param>
        /// <param name="KeyPair">The key pair it belongs to.</param>
        /// <param name="Issuer">What issued it, or null for a root.</param>
        public IssuedCertificate(PnCCertificate           Certificate,
                                 AsymmetricCipherKeyPair  KeyPair,
                                 IssuedCertificate?       Issuer        = null)
        {

            this.Certificate  = Certificate ?? throw new ArgumentNullException(nameof(Certificate));
            this.KeyPair      = KeyPair     ?? throw new ArgumentNullException(nameof(KeyPair));
            this.Issuer       = Issuer;

        }

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => Issuer is null
                   ? $"{Certificate.CommonName} (self-signed)"
                   : $"{Certificate.CommonName} <- {Issuer.Certificate.CommonName}";

        #endregion

    }

}
