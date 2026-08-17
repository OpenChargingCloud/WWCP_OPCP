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
    /// What the contract provisioning service signed, on its way back to the mobility operator
    /// that asked for it.
    /// </summary>
    /// <remarks>
    /// <code>
    /// "SignedContractDataResponse": {
    ///   "required": [ "emaid", "xsdMsgDefNamespace", "signedData",
    ///                 "cpsV2GRootCertificateFingerprint", "cpsRootDistinguishedName" ],
    ///   "properties": {
    ///     "pcid":                             { "nullable": true },   // null: none was given
    ///     "emaid":                            { },
    ///     "xsdMsgDefNamespace":               { },
    ///     "signedData":                       { },   // the CertificateInstallationRes, base64
    ///     "cpsV2GRootCertificateFingerprint": { },
    ///     "cpsRootDistinguishedName":         { },
    ///     "metaData":                         { }
    ///   }
    /// }
    /// </code>
    /// The deprecated <c>CreateSignedContractDataResponse</c> carries the same fields and insists
    /// on a different subset of them, so one type serves both.
    /// <para>
    /// The last two are marked informative in the specification and are not: they say which V2G
    /// root this signature can be verified against, which is the whole of what an operator needs
    /// to know whether the cars it wrote this contract for will accept it.
    /// </para>
    /// </remarks>
    public class SignedContractDataResponse
    {

        #region Properties

        /// <summary>
        /// The contract.
        /// </summary>
        [Mandatory]
        public EMA_Id                EMAId                              { get; }

        /// <summary>
        /// What was signed, ready to be handed to a vehicle: an ISO 15118 certificate
        /// installation response.
        /// </summary>
        [Mandatory]
        public Byte[]                SignedData                         { get; }

        /// <summary>
        /// The ISO 15118 generation the signature was made for.
        /// </summary>
        [Mandatory]
        public XSD_MsgDefNamespace   XSDMsgDefNamespace                 { get; }

        /// <summary>
        /// The vehicle, when the operator named one. Absent means it did not - and that the
        /// signed contract was not filed in the contract certificate pool.
        /// </summary>
        [Optional]
        public PCID?                 PCID                               { get; }

        /// <summary>
        /// The V2G root the signature is anchored to. A vehicle that trusts a different one
        /// cannot verify this contract.
        /// </summary>
        [Optional]
        public String?               CpsV2GRootCertificateFingerprint   { get; }

        /// <summary>
        /// The distinguished name of that root.
        /// </summary>
        [Optional]
        public String?               CpsRootDistinguishedName           { get; }

        /// <summary>
        /// Whatever the operator asked to have carried along.
        /// </summary>
        [Optional]
        public String?               Metadata                           { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new signed contract data response.
        /// </summary>
        /// <param name="EMAId">The contract.</param>
        /// <param name="SignedData">The signed certificate installation response.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="PCID">The vehicle, when one was named.</param>
        /// <param name="CpsV2GRootCertificateFingerprint">The V2G root the signature is anchored to.</param>
        /// <param name="CpsRootDistinguishedName">The distinguished name of that root.</param>
        /// <param name="Metadata">Whatever the operator asked to have carried along.</param>
        public SignedContractDataResponse(EMA_Id                EMAId,
                                          Byte[]                SignedData,
                                          XSD_MsgDefNamespace?  XSDMsgDefNamespace                 = null,
                                          PCID?                 PCID                               = null,
                                          String?               CpsV2GRootCertificateFingerprint   = null,
                                          String?               CpsRootDistinguishedName           = null,
                                          String?               Metadata                           = null)
        {

            this.EMAId                             = EMAId;
            this.SignedData                        = SignedData;
            this.XSDMsgDefNamespace                = XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2;
            this.PCID                              = PCID;
            this.CpsV2GRootCertificateFingerprint  = CpsV2GRootCertificateFingerprint;
            this.CpsRootDistinguishedName          = CpsRootDistinguishedName;
            this.Metadata                          = Metadata;

        }

        #endregion


        #region (static) TryParse(JSON, out SignedContractDataResponse, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of signed contract data.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="SignedContractDataResponse">The parsed response.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                              JSON,
                                       [NotNullWhen(true)]  out SignedContractDataResponse? SignedContractDataResponse,
                                       [NotNullWhen(false)] out String?                     ErrorResponse)
        {

            SignedContractDataResponse  = null;
            ErrorResponse               = null;

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

                #region SignedData            [mandatory]

                var signedText = JSON.Value<String>("signedData");

                if (signedText.IsNullOrEmpty())
                {
                    ErrorResponse = "The 'signedData' is missing!";
                    return false;
                }

                Byte[] signedData;

                try
                {
                    signedData = Convert.FromBase64String(signedText!);
                }
                catch (Exception e)
                {
                    ErrorResponse = "The 'signedData' is not valid base64: " + e.Message;
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


                SignedContractDataResponse = new SignedContractDataResponse(
                                                 emaId.Value,
                                                 signedData,
                                                 xsdMsgDefNamespace,
                                                 pcid,
                                                 JSON.Value<String>("cpsV2GRootCertificateFingerprint"),
                                                 JSON.Value<String>("cpsRootDistinguishedName"),
                                                 JSON.Value<String>("metaData") ?? JSON.Value<String>("metadata")
                                             );

                return true;

            }
            catch (Exception e)
            {
                SignedContractDataResponse  = null;
                ErrorResponse               = "The given JSON representation of signed contract data is invalid: " + e.Message;
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

                   // The specification marks this one nullable and explains that null means no
                   // vehicle was named. Absent says the same thing, and is what every other
                   // optional field here does.
                   PCID.HasValue
                       ? new JProperty("pcid",                             PCID.Value.ToString())
                       : null,

                   new JProperty("emaid",                                  EMAId.ToString()),
                   new JProperty("xsdMsgDefNamespace",                     XSDMsgDefNamespace.ToString()),
                   new JProperty("signedData",                             Convert.ToBase64String(SignedData)),

                   CpsV2GRootCertificateFingerprint.IsNotNullOrEmpty()
                       ? new JProperty("cpsV2GRootCertificateFingerprint", CpsV2GRootCertificateFingerprint)
                       : null,

                   CpsRootDistinguishedName.IsNotNullOrEmpty()
                       ? new JProperty("cpsRootDistinguishedName",         CpsRootDistinguishedName)
                       : null,

                   Metadata.IsNotNullOrEmpty()
                       ? new JProperty("metaData",                         Metadata)
                       : null

               );

        #endregion

        #region ToSignedContractData()

        /// <summary>
        /// Turn this into what the contract certificate pool stores - which an operator that
        /// signed without naming a vehicle has to do itself, once it knows which vehicle.
        /// </summary>
        /// <param name="PCID">The vehicle, when this response does not name one.</param>
        public SignedContractData ToSignedContractData(PCID? PCID = null)

            => new (EMAId,
                    PCID ?? this.PCID ?? throw new ArgumentException("This response names no vehicle, so one has to be given!",
                                                                     nameof(PCID)),
                    SignedData,
                    XSDMsgDefNamespace,
                    Metadata,
                    CpsV2GRootCertificateFingerprint);

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"signed contract {EMAId}" +
               (PCID.HasValue
                    ? $" for vehicle {PCID.Value}"
                    : "");

        #endregion

    }

}
