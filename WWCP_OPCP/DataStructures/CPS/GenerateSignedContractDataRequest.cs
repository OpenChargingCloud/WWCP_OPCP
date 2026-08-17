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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// A contract, described rather than supplied.
    ///
    /// A mobility operator without a PKI of its own has no contract certificate to hand over, so
    /// it says which contract, for which vehicle, and for how long - and the provisioning service
    /// has the mobility operator authority under the V2G root issue one, wraps its private key for
    /// that vehicle, signs the result and files it in the contract certificate pool.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "GenerateSignedContractDataRequest": {
    ///   "required": [ "contractBegins", "contractEnds", "emaid", "pcid", "xsdMsgDefNamespace" ],
    ///   "properties": {
    ///     "contractBegins":                   { "x-constraint": "@ValidDateTime" },
    ///     "contractEnds":                     { "x-constraint": "@ValidDateTime" },
    ///     "emaid":                            { },
    ///     "pcid":                             { },
    ///     "xsdMsgDefNamespace":               { },
    ///     "subscriptionUrl":                  { },
    ///     "cpsV2GRootCertificateFingerprint": { },
    ///     "metaData":                         { }
    ///   }
    /// }
    /// </code>
    /// Calling this again with the same vehicle and contract replaces what was filed before, which
    /// is how a contract is renewed.
    /// </remarks>
    public class GenerateSignedContractDataRequest
    {

        #region Properties

        /// <summary>
        /// The contract.
        /// </summary>
        [Mandatory]
        public EMA_Id                EMAId                              { get; }

        /// <summary>
        /// The vehicle it is for. Its provisioning certificate has to be in the pool, because the
        /// contract's private key is wrapped against the key in it.
        /// </summary>
        [Mandatory]
        public PCID                  PCID                               { get; }

        /// <summary>
        /// When the contract starts.
        /// </summary>
        [Mandatory]
        public DateTimeOffset        ContractBegins                     { get; }

        /// <summary>
        /// When it ends. The contract certificate is issued to expire with it.
        /// </summary>
        [Mandatory]
        public DateTimeOffset        ContractEnds                       { get; }

        /// <summary>
        /// The ISO 15118 generation the signature is to be made for.
        /// </summary>
        [Mandatory]
        public XSD_MsgDefNamespace   XSDMsgDefNamespace                 { get; }

        /// <summary>
        /// Where a vehicle can find out more about this contract.
        /// </summary>
        [Optional]
        public URL?                  SubscriptionURL                    { get; }

        /// <summary>
        /// Which V2G root the signature is to be anchored to, when the operator cares.
        /// </summary>
        [Optional]
        public String?               CpsV2GRootCertificateFingerprint   { get; }

        /// <summary>
        /// Whatever the operator wants carried along.
        /// </summary>
        [Optional]
        public String?               Metadata                           { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new request to generate and sign contract data.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle it is for.</param>
        /// <param name="ContractBegins">When the contract starts.</param>
        /// <param name="ContractEnds">When it ends.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="SubscriptionURL">Where a vehicle can find out more about this contract.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">An optional V2G root to anchor the signature to.</param>
        /// <param name="Metadata">Whatever the operator wants carried along.</param>
        public GenerateSignedContractDataRequest(EMA_Id                EMAId,
                                                 PCID                  PCID,
                                                 DateTimeOffset        ContractBegins,
                                                 DateTimeOffset        ContractEnds,
                                                 XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                                 URL?                  SubscriptionURL                    = null,
                                                 String?               CpsV2GRootCertificateFingerprint   = null,
                                                 String?               Metadata                           = null)
        {

            this.EMAId                             = EMAId;
            this.PCID                              = PCID;
            this.ContractBegins                    = ContractBegins;
            this.ContractEnds                      = ContractEnds;
            this.XSDMsgDefNamespace                = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;
            this.SubscriptionURL                   = SubscriptionURL;
            this.CpsV2GRootCertificateFingerprint  = CpsV2GRootCertificateFingerprint;
            this.Metadata                          = Metadata;

        }

        #endregion


        #region (static) TryParse(JSON, out GenerateSignedContractDataRequest, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of a request to generate and sign
        /// contract data.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="GenerateSignedContractDataRequest">The parsed request.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                                     JSON,
                                       [NotNullWhen(true)]  out GenerateSignedContractDataRequest? GenerateSignedContractDataRequest,
                                       [NotNullWhen(false)] out String?                            ErrorResponse)
        {

            GenerateSignedContractDataRequest  = null;
            ErrorResponse                      = null;

            try
            {

                #region EMAId                 [mandatory]

                var emaId = EMA_Id.TryParse(JSON.Value<String>("emaid") ?? "");

                if (!emaId.HasValue)
                {
                    ErrorResponse = "emaid : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"";
                    return false;
                }

                #endregion

                #region PCID                  [mandatory]

                var pcid = opcp.PCID.TryParse(JSON.Value<String>("pcid") ?? "");

                if (!pcid.HasValue)
                {
                    ErrorResponse = "pcid : must match \"^[a-zA-Z0-9]{17,18}$\"";
                    return false;
                }

                #endregion

                #region ContractBegins        [mandatory]

                if (!JSON.ParseMandatory("contractBegins",
                                         "contract begin",
                                         out DateTimeOffset contractBegins,
                                         out ErrorResponse))
                {
                    ErrorResponse = "The contractBegins does not match the specification";
                    return false;
                }

                #endregion

                #region ContractEnds          [mandatory]

                if (!JSON.ParseMandatory("contractEnds",
                                         "contract end",
                                         out DateTimeOffset contractEnds,
                                         out ErrorResponse))
                {
                    ErrorResponse = "The contractEnds does not match the specification";
                    return false;
                }

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

                #region SubscriptionURL       [optional]

                URL? subscriptionURL = null;

                var subscriptionURLText = JSON.Value<String>("subscriptionUrl");

                if (subscriptionURLText.IsNotNullOrEmpty())
                {

                    subscriptionURL = URL.TryParse(subscriptionURLText!);

                    if (!subscriptionURL.HasValue)
                    {
                        ErrorResponse = "subscriptionUrl : must match \"^(https?|http)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]\"";
                        return false;
                    }

                }

                #endregion


                GenerateSignedContractDataRequest = new GenerateSignedContractDataRequest(
                                                        emaId.Value,
                                                        pcid. Value,
                                                        contractBegins,
                                                        contractEnds,
                                                        xsdMsgDefNamespace,
                                                        subscriptionURL,
                                                        JSON.Value<String>("cpsV2GRootCertificateFingerprint"),
                                                        JSON.Value<String>("metaData") ?? JSON.Value<String>("metadata")
                                                    );

                return true;

            }
            catch (Exception e)
            {
                GenerateSignedContractDataRequest  = null;
                ErrorResponse                      = "The given JSON representation of a request to generate contract data is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        public JObject ToJSON()

            => JSONObject.Create(

                   new JProperty("contractBegins",                         ContractBegins.ToISO8601(false)),
                   new JProperty("contractEnds",                           ContractEnds.  ToISO8601(false)),
                   new JProperty("emaid",                                  EMAId.         ToString()),
                   new JProperty("pcid",                                   PCID.          ToString()),
                   new JProperty("xsdMsgDefNamespace",                     XSDMsgDefNamespace.ToString()),

                   SubscriptionURL.HasValue
                       ? new JProperty("subscriptionUrl",                  SubscriptionURL.Value.ToString())
                       : null,

                   CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty()
                       ? new JProperty("cpsV2GRootCertificateFingerprint", CpsV2GRootCertificateFingerprint)
                       : null,

                   Metadata.IsNotNullOrEmpty()
                       ? new JProperty("metaData",                         Metadata)
                       : null

               );

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"generate contract {EMAId} for vehicle {PCID}, until {ContractEnds:yyyy-MM-dd}";

        #endregion

    }

}
