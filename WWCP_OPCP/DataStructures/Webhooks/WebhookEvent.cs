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
    /// One thing that happened, on its way to a partner's backend.
    /// </summary>
    /// <remarks>
    /// <code>
    /// {
    ///   "timestamp":          "2026-02-03T00:00:00Z",
    ///   "eventId":            "caf56bee-f90d-4e81-a862-7e0d0f21d306",
    ///   "eventType":          "oem.contract.created",
    ///   "xsdMsgDefNamespace": "urn:iso:15118:2:2013:MsgDef",
    ///   "payload":            { ... }
    /// }
    /// </code>
    /// <para>
    /// The payload has two shapes: one for the three events about a root certificate, one for the
    /// twelve about vehicles and contracts. Both are built here rather than by whoever raises the
    /// event, so that an event cannot describe itself in a way a partner has not been told to
    /// expect.
    /// </para>
    /// <para>
    /// The narrative documentation's own example carries no <c>timestamp</c> where the payload
    /// document requires one. It is always written.
    /// </para>
    /// </remarks>
    public class WebhookEvent
    {

        #region Properties

        /// <summary>
        /// Which event this is.
        /// </summary>
        [Mandatory]
        public WebhookEventType      EventType             { get; }

        /// <summary>
        /// This particular occurrence of it. A partner uses it to recognize a delivery it has
        /// already seen, which matters because a delivery that timed out is retried.
        /// </summary>
        [Mandatory]
        public Trace_Id              EventId               { get; }

        /// <summary>
        /// When it happened.
        /// </summary>
        [Mandatory]
        public DateTimeOffset        Timestamp             { get; }

        /// <summary>
        /// What it happened to.
        /// </summary>
        [Mandatory]
        public JObject               Payload               { get; }

        /// <summary>
        /// The ISO 15118 generation it belongs to.
        /// </summary>
        [Optional]
        public XSD_MsgDefNamespace?  XSDMsgDefNamespace    { get; }


        /// <summary>
        /// The contract this event is about, when it is about one. The delivery service needs it
        /// to decide which partners may hear about this event at all.
        /// </summary>
        public EMA_Id?               EMAId
            => EMA_Id.TryParse(Payload.Value<String>("emaid") ?? "");

        /// <summary>
        /// The vehicle this event is about, when it is about one.
        /// </summary>
        public PCID?                 PCID
            => opcp.PCID.TryParse(Payload.Value<String>("pcid") ?? "");

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new webhook event.
        /// </summary>
        /// <param name="EventType">Which event this is.</param>
        /// <param name="Payload">What it happened to.</param>
        /// <param name="EventId">This particular occurrence of it.</param>
        /// <param name="Timestamp">When it happened.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation it belongs to.</param>
        public WebhookEvent(WebhookEventType      EventType,
                            JObject               Payload,
                            Trace_Id?             EventId              = null,
                            DateTimeOffset?       Timestamp            = null,
                            XSD_MsgDefNamespace?  XSDMsgDefNamespace   = null)
        {

            this.EventType           = EventType;
            this.Payload             = Payload ?? [];
            this.EventId             = EventId   ?? Trace_Id.NewRandom();
            this.Timestamp           = Timestamp ?? DateTimeOffset.UtcNow;
            this.XSDMsgDefNamespace  = XSDMsgDefNamespace;

        }

        #endregion


        #region (static) ForRootCertificate(EventType, RootCertificate, ...)

        /// <summary>
        /// An event about a root certificate.
        /// </summary>
        /// <param name="EventType">Which event this is.</param>
        /// <param name="RootCertificate">The root it is about.</param>
        /// <param name="Timestamp">When it happened.</param>
        public static WebhookEvent ForRootCertificate(WebhookEventType  EventType,
                                                      RootCertificate   RootCertificate,
                                                      DateTimeOffset?   Timestamp   = null)

            => new (EventType,

                    JSONObject.Create(

                        RootCertificate.Id.HasValue
                            ? new JProperty("rootCertificateId",   RootCertificate.Id.Value.ToString())
                            : null,

                        new JProperty("distinguishedName",         RootCertificate.DistinguishedName),
                        new JProperty("commonName",                RootCertificate.CommonName),
                        new JProperty("rootType",                  RootCertificate.RootType.ToString()),
                        new JProperty("rootSerialNumber",          RootCertificate.RootIssuerSerialNumber),

                        RootCertificate.SignatureAlgorithm.HasValue
                            ? new JProperty("signatureAlgorithm",  RootCertificate.SignatureAlgorithm.Value.ToString())
                            : null,

                        new JProperty("fingerprintSHA256",         RootCertificate.Fingerprint)

                    ),

                    Timestamp:           Timestamp,
                    XSDMsgDefNamespace:  RootCertificate.XSDMsgDefNamespace);

        #endregion

        #region (static) ForContract      (EventType, EMAId, PCID, ...)

        /// <summary>
        /// An event about a contract or the vehicle it belongs to.
        /// </summary>
        /// <param name="EventType">Which event this is.</param>
        /// <param name="EMAId">The contract.</param>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="ContractCertificate">The contract certificate, when the event carries one.</param>
        /// <param name="CpsSignerRootFingerprint">The V2G root the signature is anchored to.</param>
        /// <param name="CpsSignerRootCommonName">The common name of that root.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="Timestamp">When it happened.</param>
        public static WebhookEvent ForContract(WebhookEventType      EventType,
                                               EMA_Id                EMAId,
                                               PCID                  PCID,
                                               PnCCertificate?       ContractCertificate        = null,
                                               String?               CpsSignerRootFingerprint   = null,
                                               String?               CpsSignerRootCommonName    = null,
                                               XSD_MsgDefNamespace?  XSDMsgDefNamespace         = null,
                                               DateTimeOffset?       Timestamp                  = null)

            => new (EventType,

                    JSONObject.Create(

                        new JProperty("emaid",                            EMAId.ToString()),
                        new JProperty("pcid",                             PCID. ToString()),

                        ContractCertificate is not null
                            ? new JProperty("contractCert",               ContractCertificate.Base64)
                            : null,

                        CpsSignerRootFingerprint.IsNotNullOrEmpty()
                            ? new JProperty("cpsSignerRootFingerprint",   CpsSignerRootFingerprint)
                            : null,

                        CpsSignerRootCommonName.IsNotNullOrEmpty()
                            ? new JProperty("cpsSignerRootCommonName",    CpsSignerRootCommonName)
                            : null,

                        ContractCertificate?.SignatureAlgorithm is not null
                            ? new JProperty("signatureAlgorithm",         ContractCertificate.SignatureAlgorithm.Value.ToString())
                            : null

                    ),

                    Timestamp:           Timestamp,
                    XSDMsgDefNamespace:  XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2);

        #endregion

        #region (static) ForVehicle       (EventType, PCID, ...)

        /// <summary>
        /// An event about a vehicle rather than about one of its contracts.
        /// </summary>
        /// <param name="EventType">Which event this is.</param>
        /// <param name="PCID">The vehicle.</param>
        /// <param name="EMAId">A contract, when the event is about one in particular.</param>
        /// <param name="XSDMsgDefNamespace">The ISO 15118 generation.</param>
        /// <param name="Timestamp">When it happened.</param>
        /// <remarks>
        /// The payload document requires an EMAID beside the PCID even for the events that are
        /// about the vehicle itself - a provisioning certificate being deleted, a key pair being
        /// replaced. Where there is no single contract to name, the field is written empty rather
        /// than omitted, so that a partner reading it by name finds it.
        /// </remarks>
        public static WebhookEvent ForVehicle(WebhookEventType      EventType,
                                              PCID                  PCID,
                                              EMA_Id?               EMAId                = null,
                                              XSD_MsgDefNamespace?  XSDMsgDefNamespace   = null,
                                              DateTimeOffset?       Timestamp            = null)

            => new (EventType,

                    new JObject(
                        new JProperty("emaid",  EMAId?.ToString() ?? ""),
                        new JProperty("pcid",   PCID.  ToString())
                    ),

                    Timestamp:           Timestamp,
                    XSDMsgDefNamespace:  XSDMsgDefNamespace ?? XSD_MsgDefNamespace.ISO15118_2);

        #endregion


        #region (static) TryParse(JSON, out WebhookEvent, out ErrorResponse)

        /// <summary>
        /// Try to parse the given JSON representation of a webhook event.
        /// </summary>
        /// <param name="JSON">The JSON to parse.</param>
        /// <param name="WebhookEvent">The parsed event.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                JSON,
                                       [NotNullWhen(true)]  out WebhookEvent? WebhookEvent,
                                       [NotNullWhen(false)] out String?       ErrorResponse)
        {

            WebhookEvent   = null;
            ErrorResponse  = null;

            try
            {

                #region EventType    [mandatory]

                var eventType = WebhookEventType.TryParse(JSON.Value<String>("eventType") ?? "");

                if (!eventType.HasValue)
                {
                    ErrorResponse = "The 'eventType' is missing!";
                    return false;
                }

                #endregion

                #region Payload      [mandatory]

                if (JSON["payload"] is not JObject payload)
                {
                    ErrorResponse = "The 'payload' is missing!";
                    return false;
                }

                #endregion

                #region Timestamp    [optional here, although the payload document requires it]

                DateTimeOffset? timestamp = null;

                if (JSON["timestamp"] is not null &&
                    JSON.ParseMandatory("timestamp", "event timestamp", out DateTimeOffset parsed, out _))
                {
                    timestamp = parsed;
                }

                #endregion


                WebhookEvent = new WebhookEvent(
                                   eventType.Value,
                                   payload,
                                   Trace_Id.TryParse(JSON.Value<String>("eventId") ?? ""),
                                   timestamp,
                                   XSD_MsgDefNamespace.TryParse(JSON.Value<String>("xsdMsgDefNamespace") ?? "")
                               );

                return true;

            }
            catch (Exception e)
            {
                WebhookEvent   = null;
                ErrorResponse  = "The given JSON representation of a webhook event is invalid: " + e.Message;
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

                   new JProperty("timestamp",             Timestamp.ToISO8601(false)),
                   new JProperty("eventId",               EventId.  ToString()),
                   new JProperty("eventType",             EventType.ToString()),

                   XSDMsgDefNamespace.HasValue
                       ? new JProperty("xsdMsgDefNamespace",  XSDMsgDefNamespace.Value.ToString())
                       : null,

                   new JProperty("payload",               Payload)

               );

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{EventType} ({EventId})";

        #endregion

    }

}
