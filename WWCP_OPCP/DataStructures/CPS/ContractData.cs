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
    /// Everything a vehicle needs to start charging under a contract: the contract certificate and
    /// the chain that vouches for it, the contract's private key wrapped so that only this vehicle
    /// can unwrap it, and the ephemeral public key it needs to do so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The specification carries this in two shapes and both are in use. The current one is flat:
    /// </para>
    /// <code>
    /// "ContractData": {
    ///   "required": [ "contractCertificate", "contractSubCa1Certificate",
    ///                 "contractSignatureEncryptedPrivateKey", "dHpublickey" ],
    ///   "properties": {
    ///     "contractCertificate":                  { "maxLength": 800 },
    ///     "contractSubCa1Certificate":            { "maxLength": 800 },
    ///     "contractSubCa2Certificate":            { "maxLength": 800 },
    ///     "contractSignatureEncryptedPrivateKey": { },
    ///     "dHpublickey":                          { }
    ///   }
    /// }
    /// </code>
    /// <para>
    /// The one the two deprecated operations still take nests the certificates and adds the EMAID,
    /// which the flat form leaves to the enclosing request:
    /// </para>
    /// <code>
    /// "contract-data": {
    ///   "required": [ "contractSignatureCertChain", "contractSignatureEncryptedPrivateKey",
    ///                 "dHpublickey", "emaid" ],
    ///   "contractSignatureCertChain": {
    ///     "contractSignatureCertChainCertificate":    ...,
    ///     "contractSignatureCertChainSubCertificates": [ ... ]   // Sub-CA 2 first, then Sub-CA 1
    ///   }
    /// }
    /// </code>
    /// <para>
    /// One type reads and writes both. Note the lowercase k in <c>dHpublickey</c>, which is the
    /// specification's own spelling and one of the exceptions its naming rules admit to.
    /// </para>
    /// </remarks>
    public class ContractData
    {

        #region Properties

        /// <summary>
        /// The contract certificate. Its common name is the EMAID.
        /// </summary>
        [Mandatory]
        public PnCCertificate   ContractCertificate                    { get; }

        /// <summary>
        /// The intermediate one below the mobility operator's root.
        /// </summary>
        [Mandatory]
        public PnCCertificate   SubCA1Certificate                      { get; }

        /// <summary>
        /// The issuing intermediate, for the operators that use two.
        /// </summary>
        [Optional]
        public PnCCertificate?  SubCA2Certificate                      { get; }

        /// <summary>
        /// The contract's private key, encrypted for one vehicle: a 16-byte initialisation
        /// vector followed by the ciphertext.
        /// </summary>
        [Mandatory]
        public Byte[]           ContractSignatureEncryptedPrivateKey   { get; }

        /// <summary>
        /// The ephemeral public key the vehicle needs to unwrap that private key.
        /// </summary>
        [Mandatory]
        public Byte[]           DHPublicKey                            { get; }

        /// <summary>
        /// The contract, carried explicitly by the nested form and read from the certificate
        /// otherwise.
        /// </summary>
        [Optional]
        public EMA_Id?          EMAId                                  { get; }


        /// <summary>
        /// The contract this data is for. Taken from the certificate's common name, which is
        /// where ISO 15118 puts it, and from the explicit field when the certificate does not
        /// name one.
        /// </summary>
        public EMA_Id?          Contract
            => EMA_Id.TryParse(ContractCertificate.CommonName) ?? EMAId;

        /// <summary>
        /// The intermediates, nearest the contract first - the order a chain is walked in, and
        /// the order the nested form lists them in.
        /// </summary>
        public IEnumerable<PnCCertificate> SubCAs
            => SubCA2Certificate is not null
                   ? [ SubCA2Certificate, SubCA1Certificate ]
                   : [ SubCA1Certificate ];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create new contract data.
        /// </summary>
        /// <param name="ContractCertificate">The contract certificate.</param>
        /// <param name="SubCA1Certificate">The intermediate one below the operator's root.</param>
        /// <param name="ContractSignatureEncryptedPrivateKey">The wrapped contract private key.</param>
        /// <param name="DHPublicKey">The ephemeral public key that unwraps it.</param>
        /// <param name="SubCA2Certificate">An optional issuing intermediate.</param>
        /// <param name="EMAId">An optional explicit contract identification.</param>
        public ContractData(PnCCertificate   ContractCertificate,
                            PnCCertificate   SubCA1Certificate,
                            Byte[]           ContractSignatureEncryptedPrivateKey,
                            Byte[]           DHPublicKey,
                            PnCCertificate?  SubCA2Certificate                      = null,
                            EMA_Id?          EMAId                                  = null)
        {

            this.ContractCertificate                   = ContractCertificate ?? throw new ArgumentNullException(nameof(ContractCertificate));
            this.SubCA1Certificate                     = SubCA1Certificate   ?? throw new ArgumentNullException(nameof(SubCA1Certificate));
            this.ContractSignatureEncryptedPrivateKey  = ContractSignatureEncryptedPrivateKey;
            this.DHPublicKey                           = DHPublicKey;
            this.SubCA2Certificate                     = SubCA2Certificate;
            this.EMAId                                 = EMAId;

        }

        #endregion


        #region (static) TryParse(JSON, out ContractData, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of contract data, in either shape.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="ContractData">The parsed contract data.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                     JSON,
                                       [NotNullWhen(true)]  out ContractData?      ContractData,
                                       [NotNullWhen(false)] out String?            ErrorResponse)
        {

            ContractData   = null;
            ErrorResponse  = null;

            try
            {

                PnCCertificate?  contractCertificate;
                PnCCertificate?  subCA1Certificate   = null;
                PnCCertificate?  subCA2Certificate   = null;

                #region The nested shape, as the deprecated operations take it

                if (JSON["contractSignatureCertChain"] is JObject chain)
                {

                    if (!TryReadCertificate(chain, "contractSignatureCertChainCertificate", out contractCertificate, out ErrorResponse))
                        return false;

                    // "Sub-CA 2 first, then Sub-CA 1" - deepest first, which is also the order
                    // a chain is walked in.
                    var subCertificates = (chain["contractSignatureCertChainSubCertificates"] as JArray)?.
                                              Select(token => token.Value<String>() ?? "").
                                              ToArray() ?? [];

                    if (subCertificates.Length == 0)
                    {
                        ErrorResponse = "Invalid certificate format on contractSignatureCertChainSubCertificates list: it is empty!";
                        return false;
                    }

                    var parsed = new List<PnCCertificate>();

                    foreach (var text in subCertificates)
                    {
                        if (!PnCCertificate.TryParse(text, out var certificate, out var why))
                        {
                            ErrorResponse = $"Invalid certificate format on contractSignatureCertChainSubCertificates list: {why}";
                            return false;
                        }
                        parsed.Add(certificate);
                    }

                    if (parsed.Count == 1)
                        subCA1Certificate = parsed[0];
                    else
                    {
                        subCA2Certificate = parsed[0];
                        subCA1Certificate = parsed[1];
                    }

                }

                #endregion

                #region The current, flat shape

                else
                {

                    if (!TryReadCertificate(JSON, "contractCertificate",       out contractCertificate, out ErrorResponse))
                        return false;

                    if (!TryReadCertificate(JSON, "contractSubCa1Certificate", out subCA1Certificate,   out ErrorResponse))
                        return false;

                    if (JSON["contractSubCa2Certificate"] is not null &&
                       !TryReadCertificate(JSON, "contractSubCa2Certificate", out subCA2Certificate, out ErrorResponse))
                    {
                        return false;
                    }

                }

                #endregion

                #region The wrapped private key and the key that unwraps it

                if (!TryReadBase64(JSON, "contractSignatureEncryptedPrivateKey", out var encryptedPrivateKey, out ErrorResponse))
                    return false;

                if (!TryReadBase64(JSON, "dHpublickey", out var dhPublicKey, out ErrorResponse))
                    return false;

                #endregion

                #region EMAId    [only the nested shape carries it]

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


                ContractData = new ContractData(
                                   contractCertificate,
                                   subCA1Certificate,
                                   encryptedPrivateKey,
                                   dhPublicKey,
                                   subCA2Certificate,
                                   emaId
                               );

                return true;

            }
            catch (Exception e)
            {
                ContractData   = null;
                ErrorResponse  = "The given JSON representation of contract data is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(Nested = false)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="Nested">
        /// Whether to write the nested shape the two deprecated operations take, rather than the
        /// current flat one.
        /// </param>
        public JObject ToJSON(Boolean Nested = false)
        {

            if (Nested)
                return JSONObject.Create(

                           new JProperty("contractSignatureCertChain",
                               JSONObject.Create(
                                   new JProperty("contractSignatureCertChainCertificate",     ContractCertificate.Base64),
                                   new JProperty("contractSignatureCertChainSubCertificates", new JArray(SubCAs.Select(subCA => subCA.Base64)))
                               )),

                           new JProperty("contractSignatureEncryptedPrivateKey",  Convert.ToBase64String(ContractSignatureEncryptedPrivateKey)),
                           new JProperty("dHpublickey",                           Convert.ToBase64String(DHPublicKey)),

                           Contract.HasValue
                               ? new JProperty("emaid",                           Contract.Value.ToString())
                               : null

                       );

            return JSONObject.Create(

                       new JProperty("contractCertificate",                       ContractCertificate.Base64),
                       new JProperty("contractSubCa1Certificate",                 SubCA1Certificate.  Base64),

                       SubCA2Certificate is not null
                           ? new JProperty("contractSubCa2Certificate",           SubCA2Certificate.Base64)
                           : null,

                       new JProperty("contractSignatureEncryptedPrivateKey",      Convert.ToBase64String(ContractSignatureEncryptedPrivateKey)),
                       new JProperty("dHpublickey",                               Convert.ToBase64String(DHPublicKey))

                   );

        }

        #endregion


        #region (private, static) TryReadCertificate / TryReadBase64

        private static Boolean TryReadCertificate(JObject                                   JSON,
                                                  String                                    PropertyName,
                                                  [NotNullWhen(true)]  out PnCCertificate?  Certificate,
                                                  [NotNullWhen(false)] out String?          ErrorResponse)
        {

            Certificate    = null;
            ErrorResponse  = null;

            var text = JSON.Value<String>(PropertyName);

            if (text.IsNullOrEmpty())
            {
                ErrorResponse = $"Invalid certificate format on {PropertyName}: it is missing!";
                return false;
            }

            if (!PnCCertificate.TryParse(text!, out Certificate, out var why))
            {
                ErrorResponse = $"Invalid certificate format on {PropertyName}: {why}";
                return false;
            }

            return true;

        }

        private static Boolean TryReadBase64(JObject                           JSON,
                                             String                            PropertyName,
                                             out Byte[]                        Bytes,
                                             [NotNullWhen(false)] out String?  ErrorResponse)
        {

            Bytes          = [];
            ErrorResponse  = null;

            var text = JSON.Value<String>(PropertyName);

            if (text.IsNullOrEmpty())
            {
                ErrorResponse = $"The '{PropertyName}' is missing!";
                return false;
            }

            try
            {
                Bytes = Convert.FromBase64String(text!);
                return true;
            }
            catch (Exception e)
            {
                ErrorResponse = $"The '{PropertyName}' is not valid base64: {e.Message}";
                return false;
            }

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"contract data for {Contract?.ToString() ?? ContractCertificate.CommonName}";

        #endregion

    }

}
