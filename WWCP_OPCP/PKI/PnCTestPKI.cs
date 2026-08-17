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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A whole Plug&amp;Charge public key infrastructure, built in this process.
    ///
    /// ISO 15118 does not have one PKI but three that meet in the vehicle: a V2G root anchoring
    /// the charging infrastructure, the contract provisioning service and - for operators without
    /// their own - the mobility operator; an OEM root anchoring the certificate a vehicle is born
    /// with; and, for a mobility operator that brings its own, a root of its own. Each is
    /// Root → Sub-CA 1 → Sub-CA 2 → leaf, as ISO 15118-2 prescribes.
    ///
    /// This exists so that an ecosystem can be started, and tested, without any of that having to
    /// be arranged first.
    /// </summary>
    /// <remarks>
    /// The name is meant literally: these keys are generated in memory by whoever calls this, and
    /// nothing about them is secret. A real ecosystem's roots live in an HSM and arrive out of
    /// band, which is a process this class does not and should not model.
    /// </remarks>
    public class PnCTestPKI
    {

        #region Data

        /// <summary>
        /// How long the roots live. Long, because a root that expired mid-test would fail
        /// everything for a reason unrelated to what was being tested.
        /// </summary>
        public static readonly TimeSpan DefaultRootLifetime  = TimeSpan.FromDays(40 * 365);

        /// <summary>
        /// How long the sub-CAs live.
        /// </summary>
        public static readonly TimeSpan DefaultSubCALifetime = TimeSpan.FromDays(10 * 365);

        /// <summary>
        /// How long the leaf certificates live.
        /// </summary>
        public static readonly TimeSpan DefaultLeafLifetime  = TimeSpan.FromDays(2 * 365);

        #endregion

        #region Properties

        /// <summary>
        /// The curve every key in this infrastructure is on.
        /// </summary>
        public SignatureAlgorithm  Algorithm             { get; }


        /// <summary>The V2G root: the charging infrastructure's trust anchor.</summary>
        public IssuedCertificate   V2GRoot               { get; }

        /// <summary>The vehicle manufacturers' trust anchor.</summary>
        public IssuedCertificate   OEMRoot               { get; }

        /// <summary>The trust anchor of a mobility operator that brings its own PKI.</summary>
        public IssuedCertificate   MORoot                { get; }

        /// <summary>A root belonging to nobody in this ecosystem, for testing what happens
        /// when a certificate chains somewhere unexpected.</summary>
        public IssuedCertificate   UntrustedRoot         { get; }


        /// <summary>Charge point operator sub-CA, one below the V2G root.</summary>
        public IssuedCertificate   CPOSubCA1             { get; }

        /// <summary>Charge point operator sub-CA, the issuing one.</summary>
        public IssuedCertificate   CPOSubCA2             { get; }

        /// <summary>Contract provisioning service sub-CA, one below the V2G root.</summary>
        public IssuedCertificate   CPSSubCA1             { get; }

        /// <summary>Contract provisioning service sub-CA, the issuing one.</summary>
        public IssuedCertificate   CPSSubCA2             { get; }

        /// <summary>Mobility operator sub-CA of the V2G PKI, one below the V2G root.</summary>
        public IssuedCertificate   V2GMOSubCA1           { get; }

        /// <summary>Mobility operator sub-CA of the V2G PKI, the issuing one.</summary>
        public IssuedCertificate   V2GMOSubCA2           { get; }

        /// <summary>Vehicle manufacturer sub-CA, one below the OEM root.</summary>
        public IssuedCertificate   OEMSubCA1             { get; }

        /// <summary>Vehicle manufacturer sub-CA, the issuing one.</summary>
        public IssuedCertificate   OEMSubCA2             { get; }

        /// <summary>Sub-CA of a mobility operator's own PKI, one below its root.</summary>
        public IssuedCertificate   MOSubCA1              { get; }

        /// <summary>Sub-CA of a mobility operator's own PKI, the issuing one.</summary>
        public IssuedCertificate   MOSubCA2              { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Build a whole Plug&amp;Charge public key infrastructure.
        /// </summary>
        /// <param name="Algorithm">The curve to use, or secp256r1 - the only one ISO 15118-2 has.</param>
        /// <param name="Name">An optional name to distinguish this infrastructure from another.</param>
        public PnCTestPKI(SignatureAlgorithm?  Algorithm   = null,
                          String?              Name        = null)
        {

            this.Algorithm  = Algorithm ?? SignatureAlgorithm.secp256r1;

            var suffix      = Name.IsNotNullOrEmpty() ? $" {Name}" : "";

            #region The three roots, and one nobody trusts

            V2GRoot        = Root($"V2G Root CA{suffix}");
            OEMRoot        = Root($"OEM Root CA{suffix}");
            MORoot         = Root($"MO Root CA{suffix}");
            UntrustedRoot  = Root($"Untrusted Root CA{suffix}");

            #endregion

            #region The V2G PKI: charging stations, contract signing, and operators without their own PKI

            CPOSubCA1    = SubCA($"CPO Sub-CA 1{suffix}",     V2GRoot,      1);
            CPOSubCA2    = SubCA($"CPO Sub-CA 2{suffix}",     CPOSubCA1,    0);

            CPSSubCA1    = SubCA($"CPS Sub-CA 1{suffix}",     V2GRoot,      1);
            CPSSubCA2    = SubCA($"CPS Sub-CA 2{suffix}",     CPSSubCA1,    0);

            V2GMOSubCA1  = SubCA($"MO Sub-CA 1{suffix}",      V2GRoot,      1);
            V2GMOSubCA2  = SubCA($"MO Sub-CA 2{suffix}",      V2GMOSubCA1,  0);

            #endregion

            #region The OEM PKI: the certificate a vehicle is born with

            OEMSubCA1    = SubCA($"OEM Sub-CA 1{suffix}",     OEMRoot,      1);
            OEMSubCA2    = SubCA($"OEM Sub-CA 2{suffix}",     OEMSubCA1,    0);

            #endregion

            #region A mobility operator's own PKI

            MOSubCA1     = SubCA($"MO Own Sub-CA 1{suffix}",  MORoot,       1);
            MOSubCA2     = SubCA($"MO Own Sub-CA 2{suffix}",  MOSubCA1,     0);

            #endregion

        }

        #endregion


        #region IssueProvisioningCertificate(PCID, LifeTime = null)

        /// <summary>
        /// Issue the certificate a vehicle is born with, under the manufacturers' root.
        /// </summary>
        /// <param name="PCID">The vehicle. It becomes the certificate's common name.</param>
        /// <param name="LifeTime">An optional lifetime.</param>
        public IssuedCertificate IssueProvisioningCertificate(PCID       PCID,
                                                              TimeSpan?  LifeTime   = null)

            => Leaf(PCID.ToString(), OEMSubCA2, LifeTime);

        #endregion

        #region IssueContractCertificate    (EMAId, OwnPKI = false, LifeTime = null)

        /// <summary>
        /// Issue a contract certificate.
        /// </summary>
        /// <param name="EMAId">The contract. It becomes the certificate's common name.</param>
        /// <param name="OwnPKI">
        /// Whether the mobility operator brings its own PKI. False issues under the ecosystem's
        /// V2G root, which is the path for an operator that does not.
        /// </param>
        /// <param name="LifeTime">An optional lifetime.</param>
        public IssuedCertificate IssueContractCertificate(EMA_Id     EMAId,
                                                          Boolean    OwnPKI     = false,
                                                          TimeSpan?  LifeTime   = null)

            => Leaf(EMAId.ToString(),
                    OwnPKI ? MOSubCA2 : V2GMOSubCA2,
                    LifeTime);

        #endregion

        #region IssueSECCCertificate        (SECCId, LifeTime = null)

        /// <summary>
        /// Issue the certificate of a charging station's communication controller.
        /// </summary>
        /// <param name="SECCId">The EVSEID or SECCID. It becomes the certificate's common name.</param>
        /// <param name="LifeTime">An optional lifetime.</param>
        public IssuedCertificate IssueSECCCertificate(String     SECCId,
                                                      TimeSpan?  LifeTime   = null)

            => Leaf(SECCId, CPOSubCA2, LifeTime);

        #endregion

        #region IssueCPSSigningCertificate  (Name = null, LifeTime = null)

        /// <summary>
        /// Issue the certificate a contract provisioning service signs contract data with.
        /// </summary>
        /// <param name="Name">An optional common name.</param>
        /// <param name="LifeTime">An optional lifetime - three months in the specification's own example.</param>
        public IssuedCertificate IssueCPSSigningCertificate(String?    Name       = null,
                                                            TimeSpan?  LifeTime   = null)

            => Leaf(Name ?? "CPS Provisioning Signer",
                    CPSSubCA2,
                    LifeTime ?? TimeSpan.FromDays(90));

        #endregion

        #region IssueUntrusted              (CommonName, LifeTime = null)

        /// <summary>
        /// Issue a certificate that chains to nothing this ecosystem knows.
        ///
        /// Everything about it is well-formed. It is refused for the one reason that matters -
        /// nobody here has any reason to believe its root.
        /// </summary>
        /// <param name="CommonName">The common name.</param>
        /// <param name="LifeTime">An optional lifetime.</param>
        public IssuedCertificate IssueUntrusted(String     CommonName,
                                                TimeSpan?  LifeTime   = null)

            => Leaf(CommonName, UntrustedRoot, LifeTime);

        #endregion


        #region (private) NewKeyPair()

        /// <summary>
        /// Generate a key pair on this infrastructure's curve.
        /// </summary>
        private AsymmetricCipherKeyPair NewKeyPair()

            => Algorithm == SignatureAlgorithm.ed448
                   ? PKIFactory.GenerateEd448KeyPair()
                   : PKIFactory.GenerateECCKeyPair(Algorithm.ToString());

        #endregion

        #region (private) Root (CommonName, LifeTime = null)

        /// <summary>
        /// Create a self-signed root.
        /// </summary>
        private IssuedCertificate Root(String     CommonName,
                                       TimeSpan?  LifeTime   = null)
        {

            var keyPair = NewKeyPair();

            return new IssuedCertificate(
                       PnCCertificate.From(
                           PKIFactory.CreateRootCACertificate(
                               CommonName,
                               keyPair,
                               LifeTime ?? DefaultRootLifetime
                           )
                       ),
                       keyPair
                   );

        }

        #endregion

        #region (private) SubCA(CommonName, Issuer, PathLenConstraint, LifeTime = null)

        /// <summary>
        /// Create an intermediate certification authority.
        /// </summary>
        private IssuedCertificate SubCA(String             CommonName,
                                        IssuedCertificate  Issuer,
                                        Byte               PathLenConstraint,
                                        TimeSpan?          LifeTime            = null)
        {

            var keyPair = NewKeyPair();

            return new IssuedCertificate(
                       PnCCertificate.From(
                           PKIFactory.CreateIntermediateCA(
                               CommonName,
                               keyPair.Public,
                               Issuer.PrivateKey,
                               Issuer.Certificate.BouncyCastleCertificate,
                               LifeTime ?? DefaultSubCALifetime,
                               PathLenConstraint
                           )
                       ),
                       keyPair,
                       Issuer
                   );

        }

        #endregion

        #region (private) Leaf (CommonName, Issuer, LifeTime = null)

        /// <summary>
        /// Create an end entity certificate.
        ///
        /// Every ISO 15118 leaf identifies something - a vehicle, a contract, a charging station -
        /// and the identifier is the common name. Nothing else in the certificate carries it, which
        /// is why validating one means comparing the common name against what was asked for.
        /// </summary>
        private IssuedCertificate Leaf(String             CommonName,
                                       IssuedCertificate  Issuer,
                                       TimeSpan?          LifeTime     = null)
        {

            var keyPair = NewKeyPair();

            return new IssuedCertificate(
                       PnCCertificate.From(
                           PKIFactory.SignClientCertificate(
                               CommonName,
                               keyPair.Public,
                               Issuer.PrivateKey,
                               Issuer.Certificate.BouncyCastleCertificate,
                               LifeTime ?? DefaultLeafLifetime
                           )
                       ),
                       keyPair,
                       Issuer
                   );

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"a Plug&Charge PKI on {Algorithm}: {V2GRoot.Certificate.CommonName}, " +
               $"{OEMRoot.Certificate.CommonName}, {MORoot.Certificate.CommonName}";

        #endregion

    }

}
