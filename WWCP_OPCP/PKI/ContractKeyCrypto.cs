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

using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A contract's private key, wrapped so that only one vehicle can unwrap it.
    /// </summary>
    /// <param name="EncryptedPrivateKey">The wrapped key: a 16-byte initialisation vector followed by the ciphertext.</param>
    /// <param name="DHPublicKey">The ephemeral public key the vehicle needs to unwrap it.</param>
    public sealed record WrappedContractKey(Byte[] EncryptedPrivateKey,
                                            Byte[] DHPublicKey);


    /// <summary>
    /// Wraps a contract's private key for one particular vehicle.
    ///
    /// A contract certificate is worth nothing without its private key, and the key has to reach
    /// the vehicle across a charging station that must not learn it. ISO 15118 solves this with an
    /// ephemeral key agreement: whoever issues the contract generates a throwaway key pair, agrees
    /// a secret with the public key in the vehicle's provisioning certificate, encrypts the
    /// contract's private key with it, and sends the throwaway public key along. Only the vehicle -
    /// the one holder of the provisioning private key - can arrive at the same secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The key derivation here is this library's own, not ISO 15118-2's.</b> The shape is right -
    /// ephemeral ECDH against the provisioning certificate's key, AES-128 in CBC mode, a 16-byte
    /// initialisation vector in front of the ciphertext, which is what produces the 48-byte value
    /// the specification's examples show for a P-256 contract key. What is not reproduced is
    /// ISO 15118-2's exact derivation of the session key from the agreed secret. Nothing in OPCP
    /// looks inside these bytes, so nothing in this library needs it; a real vehicle does, and it
    /// arrives with the ISO codec through the seams in <see cref="IContractDataSigner"/>.
    /// </para>
    /// <para>
    /// Until then this is what it says on the tin: a real key agreement and a real encryption,
    /// round-tripping between a contract provisioning service and a vehicle, and not interoperable
    /// with anybody else's implementation.
    /// </para>
    /// </remarks>
    public static class ContractKeyCrypto
    {

        #region Data

        /// <summary>
        /// The size of the initialisation vector prefixed to the ciphertext.
        /// </summary>
        public const Int32 IVLength = 16;

        #endregion


        #region Wrap  (ContractPrivateKey, VehicleCertificate)

        /// <summary>
        /// Wrap a contract's private key so that only the given vehicle can unwrap it.
        /// </summary>
        /// <param name="ContractPrivateKey">The contract's private key.</param>
        /// <param name="VehicleCertificate">The vehicle's provisioning certificate.</param>
        public static WrappedContractKey Wrap(AsymmetricKeyParameter  ContractPrivateKey,
                                              PnCCertificate          VehicleCertificate)
        {

            if (VehicleCertificate.BouncyCastleCertificate.GetPublicKey() is not ECPublicKeyParameters vehiclePublicKey)
                throw new ArgumentException("The vehicle's certificate does not carry an elliptic curve key!",
                                            nameof(VehicleCertificate));

            // A throwaway key pair on the vehicle's own curve - the agreement only works if
            // both sides are on the same one.
            var ephemeral      = PKIFactory.GenerateECCKeyPair(CurveNameOf(vehiclePublicKey));

            var sessionKey     = DeriveSessionKey((ECPrivateKeyParameters) ephemeral.Private,
                                                  vehiclePublicKey);

            var iv             = RandomNumberGenerator.GetBytes(IVLength);
            var plaintext      = PrivateKeyBytes(ContractPrivateKey);

            using var aes      = Aes.Create();
            aes.Key            = sessionKey;
            aes.IV             = iv;
            aes.Mode           = CipherMode.CBC;
            aes.Padding        = PaddingMode.PKCS7;

            var ciphertext     = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

            return new WrappedContractKey(
                       [.. iv, .. ciphertext],
                       ((ECPublicKeyParameters) ephemeral.Public).Q.GetEncoded(false)
                   );

        }

        #endregion

        #region Unwrap(WrappedKey, VehiclePrivateKey, VehicleCertificate)

        /// <summary>
        /// Unwrap a contract's private key, as the vehicle does.
        /// </summary>
        /// <param name="WrappedKey">The wrapped key and the ephemeral public key that goes with it.</param>
        /// <param name="VehiclePrivateKey">The vehicle's provisioning private key.</param>
        /// <param name="VehicleCertificate">The vehicle's provisioning certificate, for its curve.</param>
        public static Byte[] Unwrap(WrappedContractKey      WrappedKey,
                                    AsymmetricKeyParameter  VehiclePrivateKey,
                                    PnCCertificate          VehicleCertificate)
        {

            if (VehiclePrivateKey is not ECPrivateKeyParameters vehiclePrivateKey)
                throw new ArgumentException("The vehicle's key is not an elliptic curve key!",
                                            nameof(VehiclePrivateKey));

            if (WrappedKey.EncryptedPrivateKey.Length <= IVLength)
                throw new ArgumentException("The wrapped key is too short to carry an initialisation vector!",
                                            nameof(WrappedKey));

            var parameters   = vehiclePrivateKey.Parameters;

            var ephemeral    = new ECPublicKeyParameters(
                                   parameters.Curve.DecodePoint(WrappedKey.DHPublicKey),
                                   parameters
                               );

            var sessionKey   = DeriveSessionKey(vehiclePrivateKey, ephemeral);

            var iv           = WrappedKey.EncryptedPrivateKey[..IVLength];
            var ciphertext   = WrappedKey.EncryptedPrivateKey[IVLength..];

            using var aes    = Aes.Create();
            aes.Key          = sessionKey;

            return aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);

        }

        #endregion


        #region (private, static) DeriveSessionKey(PrivateKey, PublicKey)

        /// <summary>
        /// Agree a secret and turn it into an AES-128 key.
        /// </summary>
        /// <remarks>
        /// Both sides reach the same shared secret from opposite halves of the two key pairs;
        /// that is what elliptic curve Diffie-Hellman is for. Hashing it down to sixteen bytes is
        /// this library's own step - see the note on the class.
        /// </remarks>
        private static Byte[] DeriveSessionKey(ECPrivateKeyParameters  PrivateKey,
                                               ECPublicKeyParameters   PublicKey)
        {

            var agreement = new ECDHBasicAgreement();
            agreement.Init(PrivateKey);

            var shared    = agreement.CalculateAgreement(PublicKey).ToByteArrayUnsigned();

            return SHA256.HashData(shared)[..16];

        }

        #endregion

        #region (private, static) CurveNameOf(PublicKey)

        /// <summary>
        /// The name of the curve a key is on, so that the ephemeral pair can be generated on it.
        /// </summary>
        private static String CurveNameOf(ECPublicKeyParameters PublicKey)

            => PublicKey.Parameters.Curve.FieldSize switch {
                   256  => "secp256r1",
                   521  => "secp521r1",
                   _    => throw new NotSupportedException($"Contract keys on a {PublicKey.Parameters.Curve.FieldSize}-bit curve are not supported!")
               };

        #endregion

        #region (private, static) PrivateKeyBytes(PrivateKey)

        /// <summary>
        /// The raw scalar of a private key - what ISO 15118 transports, rather than a
        /// structured encoding of it.
        /// </summary>
        private static Byte[] PrivateKeyBytes(AsymmetricKeyParameter PrivateKey)

            => PrivateKey is ECPrivateKeyParameters ecPrivateKey
                   ? ecPrivateKey.D.ToByteArrayUnsigned()
                   : throw new ArgumentException("The contract's key is not an elliptic curve key!",
                                                 nameof(PrivateKey));

        #endregion

    }

}
