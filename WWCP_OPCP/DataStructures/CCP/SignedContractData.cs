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

using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// One contract, signed by a contract provisioning service and waiting in the pool for the
    /// car it belongs to to plug in somewhere.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "SignedContractDataRequest": {
    ///   "required": [ "xsdMsgDefNamespace", "emaid", "pcid", "signedContractDataXML" ],
    ///   "properties": {
    ///     "emaid":                            { },
    ///     "pcid":                             { },
    ///     "signedContractDataXML":            { },   // base64, as the CPS produced it
    ///     "metadata":                         { },
    ///     "cpsV2GRootCertificateFingerprint": { }
    ///   }
    /// }
    /// </code>
    /// The pool does not sign anything and does not alter what it was given: what the provisioning
    /// service signed is what the vehicle will verify, so it is stored and handed on unchanged.
    /// </remarks>
    public class SignedContractData
    {

        #region Properties

        /// <summary>
        /// The contract.
        /// </summary>
        [Mandatory]
        public EMA_Id               EMAId                              { get; }

        /// <summary>
        /// The vehicle the contract was written for.
        /// </summary>
        [Mandatory]
        public PCID                 PCID                               { get; }

        /// <summary>
        /// What the contract provisioning service signed, byte for byte.
        /// </summary>
        [Mandatory]
        public Byte[]               SignedContractDataXML              { get; }

        /// <summary>
        /// The ISO 15118 generation.
        /// </summary>
        [Mandatory]
        public XSD_MsgDefNamespace  XSDMsgDefNamespace                 { get; }

        /// <summary>
        /// Whatever the operator wanted carried along.
        /// </summary>
        [Optional]
        public String?              Metadata                           { get; }

        /// <summary>
        /// The V2G root the signing service anchors to. A vehicle that trusts a different root
        /// cannot verify this contract, which is how the pool decides what to answer with.
        /// </summary>
        [Optional]
        public String?              CpsV2GRootCertificateFingerprint   { get; }


        /// <summary>
        /// Whether this is the contract to install when the vehicle expresses no preference.
        ///
        /// ISO 15118-2 can install exactly one, so for that generation this is simply the contract
        /// the pool answers with.
        /// </summary>
        public Boolean              IsDefault                          { get; }

        /// <summary>
        /// The contract certificate, read out of the signed data by the pool. It is what the pool
        /// publishes when a manufacturer asks what contracts a vehicle has.
        /// </summary>
        [Optional]
        public PnCCertificate?      ContractCertificate                { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create new signed contract data.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="SignedContractDataXML">What the provisioning service signed.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="Metadata">Whatever the operator wanted carried along.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">The V2G root the signer anchors to.</param>
        /// <param name="IsDefault">Whether this is the contract to install by default.</param>
        /// <param name="ContractCertificate">The contract certificate, once the pool has read it.</param>
        public SignedContractData(EMA_Id                EMAId,
                                  PCID                  PCID,
                                  Byte[]                SignedContractDataXML,
                                  XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                  String?               Metadata                           = null,
                                  String?               CpsV2GRootCertificateFingerprint   = null,
                                  Boolean               IsDefault                          = false,
                                  PnCCertificate?       ContractCertificate                = null)
        {

            this.EMAId                             = EMAId;
            this.PCID                              = PCID;
            this.SignedContractDataXML             = SignedContractDataXML;
            this.XSDMsgDefNamespace                = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;
            this.Metadata                          = Metadata;
            this.CpsV2GRootCertificateFingerprint  = CpsV2GRootCertificateFingerprint;
            this.IsDefault                         = IsDefault;
            this.ContractCertificate               = ContractCertificate;

        }

        #endregion


        #region With(IsDefault = null, ContractCertificate = null)

        /// <summary>
        /// Return this contract with what the pool worked out about it.
        /// </summary>
        /// <param name="IsDefault">Whether it is the contract to install by default.</param>
        /// <param name="ContractCertificate">The contract certificate read out of the signed data.</param>
        public SignedContractData With(Boolean?         IsDefault             = null,
                                       PnCCertificate?  ContractCertificate   = null)

            => new (EMAId,
                    PCID,
                    SignedContractDataXML,
                    XSDMsgDefNamespace,
                    Metadata,
                    CpsV2GRootCertificateFingerprint,
                    IsDefault           ?? this.IsDefault,
                    ContractCertificate ?? this.ContractCertificate);

        #endregion

        #region (static) TryParse(JSON, out SignedContractData, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of signed contract data.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="SignedContractData">The parsed contract data.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                        JSON,
                                       [NotNullWhen(true)]  out SignedContractData?   SignedContractData,
                                       [NotNullWhen(false)] out String?               ErrorResponse)
        {

            SignedContractData  = null;
            ErrorResponse       = null;

            try
            {

                #region EMAId                    [mandatory]

                var emaId = EMA_Id.TryParse(JSON.Value<String>("emaid") ?? "");

                if (!emaId.HasValue)
                {
                    ErrorResponse = "emaid : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"";
                    return false;
                }

                #endregion

                #region PCID                     [mandatory]

                var pcid = opcp.PCID.TryParse(JSON.Value<String>("pcid") ?? "");

                if (!pcid.HasValue)
                {
                    ErrorResponse = "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"";
                    return false;
                }

                #endregion

                #region SignedContractDataXML    [mandatory]

                var signedText = JSON.Value<String>("signedContractDataXML");

                if (signedText.IsNullOrEmpty())
                {
                    ErrorResponse = "The 'signedContractDataXML' is missing!";
                    return false;
                }

                Byte[] signed;

                try
                {
                    signed = Convert.FromBase64String(signedText!);
                }
                catch (Exception e)
                {
                    ErrorResponse = "The 'signedContractDataXML' is not valid base64: " + e.Message;
                    return false;
                }

                #endregion

                #region XSDMsgDefNamespace       [mandatory]

                if (!JSON.ParseMandatory("xsdMsgDefNamespace",
                                         "ISO 15118 message definition namespace",
                                         XSD_MsgDefNamespace.TryParse,
                                         out XSD_MsgDefNamespace XSDMsgDefNamespace,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion


                SignedContractData = new SignedContractData(
                                         emaId.Value,
                                         pcid. Value,
                                         signed,
                                         XSDMsgDefNamespace,
                                         // This document spells it 'metadata' here and 'metaData'
                                         // elsewhere, and the provisioning service's document
                                         // spells it 'metaData' throughout. Both are read.
                                         JSON.Value<String>("metadata") ?? JSON.Value<String>("metaData"),
                                         JSON.Value<String>("cpsV2GRootCertificateFingerprint")
                                     );

                return true;

            }
            catch (Exception e)
            {
                SignedContractData  = null;
                ErrorResponse       = "The given JSON representation of signed contract data is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// Return a JSON representation of this object, as the contract provisioning service
        /// writes it into the pool.
        /// </summary>
        public JObject ToJSON()

            => JSONObject.Create(

                   new JProperty("emaid",                                 EMAId.             ToString()),
                   new JProperty("pcid",                                  PCID.              ToString()),
                   new JProperty("signedContractDataXML",                 Convert.ToBase64String(SignedContractDataXML)),
                   new JProperty("xsdMsgDefNamespace",                    XSDMsgDefNamespace.ToString()),

                   Metadata.IsNotNullOrEmpty()
                       ? new JProperty("metadata",                        Metadata)
                       : null,

                   CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty()
                       ? new JProperty("cpsV2GRootCertificateFingerprint", CpsV2GRootCertificateFingerprint)
                       : null

               );

        #endregion

        #region ToContractInfo()

        /// <summary>
        /// Return what the pool publishes about this contract when it is looked up or listed.
        /// </summary>
        /// <remarks>
        /// An earlier draft of the specification had a numeric <c>priority</c> here; it was
        /// replaced by the <c>defaultContract</c> flag, and one example still shows the old field.
        /// </remarks>
        public JObject ToContractInfo()

            => JSONObject.Create(

                   new JProperty("pcid",                                  PCID. ToString()),
                   new JProperty("emaid",                                 EMAId.ToString()),
                   new JProperty("xsdMsgDefNamespace",                    XSDMsgDefNamespace.ToString()),
                   new JProperty("defaultContract",                       IsDefault),

                   ContractCertificate is not null
                       ? new JProperty("contractCertificate",             ContractCertificate.Base64)
                       : null,

                   ContractCertificate is not null
                       ? new JProperty("certValidFrom",                   ContractCertificate.NotBefore.ToISO8601(false))
                       : null,

                   ContractCertificate is not null
                       ? new JProperty("certValidTo",                     ContractCertificate.NotAfter. ToISO8601(false))
                       : null,

                   CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty()
                       ? new JProperty("cpsV2GRootCertificateFingerprint", CpsV2GRootCertificateFingerprint)
                       : null

               );

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"contract {EMAId} for vehicle {PCID}{(IsDefault ? " (default)" : "")}";

        #endregion

    }

}
