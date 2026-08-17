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
    /// What a mobility operator that brings its own PKI hands the contract provisioning service:
    /// a contract it has already issued, to be signed so that a vehicle will accept it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The current operation and the two deprecated ones take the same fields and differ in which
    /// of them they insist on. The current one:
    /// </para>
    /// <code>
    /// "SignedContractDataRequest": {
    ///   "required": [ "contractData", "xsdMsgDefNamespace" ],
    ///   "properties": {
    ///     "contractData":                     { "$ref": "ContractData" },   // the flat shape
    ///     "pcid":                             { },                          // optional: names the vehicle
    ///     "xsdMsgDefNamespace":               { },
    ///     "cpsV2GRootCertificateFingerprint": { }
    ///   }
    /// }
    /// </code>
    /// <para>
    /// and the deprecated one, which also requires the vehicle and the contract and carries the
    /// nested contract data:
    /// </para>
    /// <code>
    /// "CreateSignedContractDataRequest": {
    ///   "required": [ "xsdMsgDefNamespace", "contractData", "pcid", "emaid" ],
    ///   "properties": { ... plus "metaData" }
    /// }
    /// </code>
    /// <para>
    /// One type reads and writes both; each operation enforces what it requires. The PCID decides
    /// what happens to the result rather than what it looks like: given one, the provisioning
    /// service also files the signed contract in the contract certificate pool; without one, the
    /// operator gets the signature back and files it itself.
    /// </para>
    /// <para>
    /// The metadata field is spelled <c>metaData</c> throughout this document and <c>metadata</c>
    /// in the pool's own; both are read, and each is written where it belongs.
    /// </para>
    /// </remarks>
    public class SignedContractDataRequest
    {

        #region Properties

        /// <summary>
        /// The contract certificate, the chain that vouches for it, and the contract's private
        /// key wrapped for one vehicle.
        /// </summary>
        [Mandatory]
        public ContractData          ContractData                       { get; }

        /// <summary>
        /// The ISO 15118 generation the signature is to be made for.
        /// </summary>
        [Mandatory]
        public XSD_MsgDefNamespace   XSDMsgDefNamespace                 { get; }

        /// <summary>
        /// The vehicle. Optional on the current operation, where supplying it is what asks for the
        /// result to be filed in the contract certificate pool.
        /// </summary>
        [Optional]
        public PCID?                 PCID                               { get; }

        /// <summary>
        /// The contract, as the operator states it. It has to agree with the common name of the
        /// contract certificate, which is where ISO 15118 keeps it.
        /// </summary>
        [Optional]
        public EMA_Id?               EMAId                              { get; }

        /// <summary>
        /// Whatever the operator wants carried along.
        /// </summary>
        [Optional]
        public String?               Metadata                           { get; }

        /// <summary>
        /// Which V2G root the signature is to be anchored to, when the operator cares. A vehicle
        /// can only verify a signature that chains to a root it trusts, so an operator that knows
        /// its cars names one; otherwise the provisioning service chooses.
        /// </summary>
        [Optional]
        public String?               CpsV2GRootCertificateFingerprint   { get; }


        /// <summary>
        /// The contract this request is about: what the contract certificate says, and what the
        /// request claims only when the certificate names nothing readable.
        /// </summary>
        public EMA_Id?               Contract
            => ContractData.Contract ?? EMAId;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new request to sign contract data.
        /// </summary>
        /// <param name="ContractData">The contract certificate, its chain and the wrapped key.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="PCID">An optional vehicle - naming one asks for the result to be filed in the pool.</param>
        /// <param name="EMAId">An optional explicit contract identification.</param>
        /// <param name="Metadata">Whatever the operator wants carried along.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">An optional V2G root to anchor the signature to.</param>
        public SignedContractDataRequest(ContractData          ContractData,
                                         XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                         PCID?                 PCID                               = null,
                                         EMA_Id?               EMAId                              = null,
                                         String?               Metadata                           = null,
                                         String?               CpsV2GRootCertificateFingerprint   = null)
        {

            this.ContractData                      = ContractData ?? throw new ArgumentNullException(nameof(ContractData));
            this.XSDMsgDefNamespace                = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;
            this.PCID                              = PCID;
            this.EMAId                             = EMAId;
            this.Metadata                          = Metadata;
            this.CpsV2GRootCertificateFingerprint  = CpsV2GRootCertificateFingerprint;

        }

        #endregion


        #region (static) TryParse(JSON, out SignedContractDataRequest, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of a request to sign contract data.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="SignedContractDataRequest">The parsed request.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                             JSON,
                                       [NotNullWhen(true)]  out SignedContractDataRequest? SignedContractDataRequest,
                                       [NotNullWhen(false)] out String?                    ErrorResponse)
        {

            SignedContractDataRequest  = null;
            ErrorResponse              = null;

            try
            {

                #region ContractData          [mandatory]

                if (JSON["contractData"] is not JObject contractDataJSON)
                {
                    ErrorResponse = "The 'contractData' is missing!";
                    return false;
                }

                if (!opcp.ContractData.TryParse(contractDataJSON, out var contractData, out ErrorResponse))
                    return false;

                #endregion

                #region XSDMsgDefNamespace    [mandatory]

                if (!JSON.ParseMandatory("xsdMsgDefNamespace",
                                         "ISO 15118 message definition namespace",
                                         XSD_MsgDefNamespace.TryParse,
                                         out XSD_MsgDefNamespace xsdMsgDefNamespace,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region PCID                  [optional]

                PCID? pcid = null;

                var pcidText = JSON.Value<String>("pcid");

                if (pcidText.IsNotNullOrEmpty())
                {

                    pcid = opcp.PCID.TryParse(pcidText!);

                    if (!pcid.HasValue)
                    {
                        ErrorResponse = "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"";
                        return false;
                    }

                }

                #endregion

                #region EMAId                 [optional]

                EMA_Id? emaId = null;

                var emaIdText = JSON.Value<String>("emaid");

                if (emaIdText.IsNotNullOrEmpty())
                {

                    emaId = EMA_Id.TryParse(emaIdText!);

                    if (!emaId.HasValue)
                    {
                        ErrorResponse = "emaid : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"";
                        return false;
                    }

                }

                #endregion


                SignedContractDataRequest = new SignedContractDataRequest(
                                                contractData,
                                                xsdMsgDefNamespace,
                                                pcid,
                                                emaId,
                                                JSON.Value<String>("metaData") ?? JSON.Value<String>("metadata"),
                                                JSON.Value<String>("cpsV2GRootCertificateFingerprint")
                                            );

                return true;

            }
            catch (Exception e)
            {
                SignedContractDataRequest  = null;
                ErrorResponse              = "The given JSON representation of a request to sign contract data is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(Nested = false)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="Nested">
        /// Whether to write the nested contract data the two deprecated operations take, rather
        /// than the current flat shape.
        /// </param>
        public JObject ToJSON(Boolean Nested = false)

            => JSONObject.Create(

                   new JProperty("contractData",                           ContractData.ToJSON(Nested)),
                   new JProperty("xsdMsgDefNamespace",                     XSDMsgDefNamespace.ToString()),

                   PCID.HasValue
                       ? new JProperty("pcid",                             PCID.Value.ToString())
                       : null,

                   Contract.HasValue
                       ? new JProperty("emaid",                            Contract.Value.ToString())
                       : null,

                   Metadata.IsNotNullOrEmpty()
                       ? new JProperty("metaData",                         Metadata)
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

            => $"sign contract {Contract?.ToString() ?? "?"}" +
               (PCID.HasValue
                    ? $" for vehicle {PCID.Value} and file it"
                    : "");

        #endregion

    }

}
