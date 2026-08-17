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

using System.Text;

using Org.BouncyCastle.Pkcs;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The enrollment interface of a V2G PKI service: RFC 7030, and where every certificate in the
    /// ecosystem comes from.
    ///
    /// A charging station asks for the one it authenticates to vehicles with, a manufacturer for
    /// the one a car is born with, a mobility operator for a contract's, a provisioning service
    /// for the one it signs contract data with. Which authority a request is addressed to decides
    /// what kind of certificate comes back - and what its common name has to be, because in
    /// ISO 15118 the common name <em>is</em> the identifier.
    /// </summary>
    public class EST_HTTPAPI : AOPCPHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where RFC 7030 puts an enrollment service.
        /// </summary>
        public static readonly HTTPPath  DefaultRootPath        = HTTPPath.Parse("/.well-known/est/");

        /// <summary>
        /// Where the interface document puts CA distribution: at the root, with the authority as
        /// the first path segment and no version prefix of any kind.
        /// </summary>
        public static readonly HTTPPath  DefaultCACertsPath     = HTTPPath.Root;

        /// <summary>
        /// How long an issued leaf certificate lives, unless a deployment says otherwise.
        /// </summary>
        public static readonly TimeSpan  DefaultLeafLifetime    = TimeSpan.FromDays(2 * 365);

        /// <summary>
        /// The media type of a certificates-only PKCS#7, as RFC 7030 §4.1.3 spells it.
        /// </summary>
        /// <remarks>
        /// Written as a header rather than through <see cref="OPCPContentTypes.PKCS7Mime"/>,
        /// because the HTTP layer models only a charset parameter and this one carries
        /// <c>smime-type</c>. The structure would be unambiguous either way - a signed-data with
        /// no signers is certificates-only by construction - but the parameter is what RFC 7030
        /// asks for.
        /// </remarks>
        public const           String    CertsOnlyContentType   = "application/pkcs7-mime; smime-type=certs-only";

        #endregion

        #region Properties

        /// <summary>
        /// The authorities this service issues from.
        /// </summary>
        public ICertificateAuthorityStore  Authorities        { get; }

        /// <summary>
        /// How long an issued leaf certificate lives.
        /// </summary>
        public TimeSpan                    LeafLifetime       { get; }

        /// <summary>
        /// The second mount that serves CA distribution where the interface document puts it.
        /// </summary>
        public ESTCACerts_HTTPAPI          CACertsDiscovery   { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new enrollment interface.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="Authorities">An optional store of issuing authorities, otherwise an empty in-memory one.</param>
        /// <param name="LeafLifetime">How long an issued certificate lives.</param>
        /// <param name="AccessTokenValidator">An optional validator of access tokens.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        /// <param name="CACertsPath">An optional path for the un-prefixed CA distribution.</param>
        public EST_HTTPAPI(HTTPServer                   HTTPServer,
                           ICertificateAuthorityStore?  Authorities            = null,
                           TimeSpan?                    LeafLifetime           = null,
                           IAccessTokenValidator?       AccessTokenValidator   = null,
                           HTTPPath?                    RootPath               = null,
                           HTTPPath?                    CACertsPath            = null)

            : base(HTTPServer,
                   AccessTokenValidator,
                   RootPath ?? DefaultRootPath,
                   I18NString.Create("OPCP V2G PKI enrollment service"))

        {

            this.Authorities       = Authorities ?? new InMemoryCertificateAuthorityStore();
            this.LeafLifetime      = LeafLifetime ?? DefaultLeafLifetime;

            RegisterURLTemplates();

            this.CACertsDiscovery  = new ESTCACerts_HTTPAPI(
                                         HTTPServer,
                                         this,
                                         CACertsPath ?? DefaultCACertsPath
                                     );

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            #region POST    ~/.well-known/est/{ca}/simpleenroll/{iso-version}    simpleenroll

            AddHandler(
                HTTPMethod.POST,
                Route("{ca}/simpleenroll/{iso-version}"),
                OPCPContentTypes.PKCS10,
                HTTPDelegate: SimpleEnroll
            );

            #endregion

            #region GET     ~/.well-known/est/{ca}/cacerts/{iso-version}/{algorithm}   cacerts

            // RFC 7030 puts CA distribution under the same well-known prefix as enrollment. The
            // interface document puts it at the root instead - see ESTCACerts_HTTPAPI - and both
            // are served, because a caller following either is following something written down.
            AddHandler(
                HTTPMethod.GET,
                Route("{ca}/cacerts/{iso-version}/{algorithm}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: CACerts
            );

            #endregion

        }

        #endregion


        #region SimpleEnroll(Request)

        /// <summary>
        /// Turn a certificate signing request into a certificate.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        public async Task<HTTPResponse> SimpleEnroll(HTTPRequest Request)
        {

            #region Which authority, and may this caller use it

            if (!TryParseURLParameter<CA_Id>(Request, "ca", CA_Id.TryParse,
                                             "certification authority", out var ca, out var response))
                return response;

            if (!TryAuthenticate(Request, out var tokenInfo, out response))
                return response;

            if (!TryAuthorize(Request, tokenInfo, out response, RolesFor(ca.Type)))
                return response;

            if (!TryParseURLParameter<XSD_MsgDefNamespace>(Request, "iso-version", TryParseISOVersion,
                                                           "ISO 15118 version", out _, out response))
                return response;

            #endregion

            #region The request itself

            var body = Request.HTTPBodyAsUTF8String?.Trim();

            if (body.IsNullOrEmpty())
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "This request carries no certificate signing request!");

            if (!CSRBuilder.TryParse(Unarmour(body!), out var csr, out var errorResponse))
                return Refuse(Request, HTTPStatusCode.BadRequest, errorResponse);

            #endregion

            #region What it is asking to have certified

            var commonName = csr.GetCommonName();

            if (commonName.IsNullOrEmpty())
                return Refuse(Request,
                              HTTPStatusCode.BadRequest,
                              "The certificate signing request carries no common name!");

            var refusal = CheckCommonName(ca.Type,
                                          commonName,
                                          tokenInfo,
                                          AccessTokenValidator is not null);

            if (refusal is not null)
                return Refuse(Request, refusal.Value.StatusCode, refusal.Value.Reason);

            #endregion

            #region An authority to issue from - on the curve the request asks about

            var algorithm = PnCCertificate.AlgorithmOf(csr.GetCertificationRequestInfo().SubjectPublicKeyInfo);

            var authority = await Authorities.Get(ca, algorithm)
                                ?? await Authorities.Get(ca);

            if (authority is null)
                return Refuse(Request,
                              HTTPStatusCode.NotFound,
                              $"This V2G PKI service operates no '{ca}' certification authority!");

            #endregion

            var issued = PnCCertificate.From(
                             PKIFactory.SignClientCertificate(
                                 csr,
                                 authority.PrivateKey,
                                 authority.Certificate.BouncyCastleCertificate,
                                 LeafLifetime
                             )
                         );

            // The issued certificate first, then the authorities between it and the root - and
            // not the root itself, which the recipient is supposed to already have from the root
            // certificate pool. CA distribution below is where a root does travel.
            return RespondWithCertificates(
                       Request,
                       [ issued, .. authority.Chain.SkipLast(1) ]
                   );

        }

        #endregion

        #region CACerts     (Request)

        /// <summary>
        /// Hand out the chain above one authority, so that what it issued can be verified.
        /// </summary>
        /// <param name="Request">An HTTP request.</param>
        public async Task<HTTPResponse> CACerts(HTTPRequest Request)
        {

            if (!TryParseURLParameter<CA_Id>(Request, "ca", CA_Id.TryParse,
                                             "certification authority", out var ca, out var response))
                return response;

            if (!TryAuthenticate(Request, out var tokenInfo, out response))
                return response;

            if (!TryAuthorize(Request, tokenInfo, out response, RolesFor(ca.Type)))
                return response;

            if (!TryParseURLParameter<XSD_MsgDefNamespace>(Request, "iso-version", TryParseISOVersion,
                                                           "ISO 15118 version", out _, out response))
                return response;

            if (!TryParseURLParameter<SignatureAlgorithm>(Request, "algorithm", SignatureAlgorithm.TryParse,
                                                          "signature algorithm", out var algorithm, out response))
                return response;

            var authority = await Authorities.Get(ca, algorithm);

            if (authority is null)
                return Refuse(Request,
                              HTTPStatusCode.NotFound,
                              $"This V2G PKI service operates no '{ca}' certification authority on {algorithm}!");

            // The whole path this time, root included: distribution is the operation whose point
            // is to hand over a trust anchor, and RFC 7030 §4.1.3 says as much.
            return RespondWithCertificates(Request, authority.Chain);

        }

        #endregion


        #region (private, static) RolesFor(CAType)

        /// <summary>
        /// Who may ask an authority of this kind for a certificate.
        /// </summary>
        /// <remarks>
        /// From the rights matrix rather than from the interface document, which lists the four
        /// roles once for the whole operation and so cannot say that a charge point operator has
        /// no business asking the vehicle manufacturers' authority for anything. The provisioning
        /// authority is open to a mobility operator using the V2G PKI as well, which is the one
        /// entry of the matrix that is not simply role-to-authority.
        /// </remarks>
        private static OPCPRole[] RolesFor(CA_Type CAType)
        {

            if (CAType == CA_Type.CPO)
                return [ OPCPRole.CPO ];

            if (CAType == CA_Type.MO)
                return [ OPCPRole.MO, OPCPRole.MO_V2GPKI, OPCPRole.MO_ExternalPKI ];

            if (CAType == CA_Type.OEM || CAType == CA_Type.VEH)
                return [ OPCPRole.OEM ];

            if (CAType == CA_Type.CPS)
                return [ OPCPRole.CPS, OPCPRole.MO_V2GPKI ];

            // An authority nobody has registered is one nobody can be authorized for either;
            // the lookup below answers that it does not exist.
            return [];

        }

        #endregion

        #region (private, static) CheckCommonName(CAType, CommonName, TokenInfo, EnforceScope)

        /// <summary>
        /// Check that the request asks for the kind of identifier this authority certifies, and
        /// that the caller may act for it.
        /// </summary>
        /// <returns>Nothing when the name is acceptable, and why not when it is not.</returns>
        /// <remarks>
        /// <para>
        /// This is the check the whole ecosystem downstream depends on. Nothing in a certificate
        /// says what it is for except its common name: the provisioning certificate pool reads a
        /// vehicle out of one, the contract pool a contract, a car a charging station. An
        /// authority that certified the wrong shape of name would put something into the world
        /// that every one of them would then misread.
        /// </para>
        /// <para>
        /// The wrong shape of name is the caller's mistake and gets a 400. The right shape
        /// belonging to somebody else is a different matter and gets a 403.
        /// </para>
        /// </remarks>
        private static (HTTPStatusCode StatusCode, String Reason)? CheckCommonName(CA_Type        CAType,
                                                                                   String         CommonName,
                                                                                   OPCPTokenInfo  TokenInfo,
                                                                                   Boolean        EnforceScope)
        {

            #region A charging station: an EVSEID or, for ISO 15118-20, a SECCID

            if (CAType == CA_Type.CPO)
                return EVSE_Id.TryParse(CommonName, out _) ||
                       SECC_Id.TryParse(CommonName, out _)

                           ? null
                           : (HTTPStatusCode.BadRequest,
                              "commonName : must match \"^[A-Za-z]{2}[\\*]?\\w{3}[\\*]?[E][\\w\\*]{1,30}$\"");

            #endregion

            #region A contract

            if (CAType == CA_Type.MO)
            {

                var emaId = EMA_Id.TryParse(CommonName);

                if (!emaId.HasValue)
                    return (HTTPStatusCode.BadRequest,
                            "commonName : must match \"^[A-Za-z]{2}[-]?\\w{3}[-]?\\w{9}[-]?(\\w{1})?$\"");

                if (EnforceScope && !TokenInfo.MayActFor(emaId.Value))
                    return (HTTPStatusCode.Forbidden,
                            $"The given token is not authorized for the e-mobility provider '{emaId.Value.ProviderId}'!");

                return null;

            }

            #endregion

            #region A vehicle

            if (CAType.IssuesForVehicles)
            {

                var pcid = PCID.TryParse(CommonName);

                if (!pcid.HasValue)
                    return (HTTPStatusCode.BadRequest,
                            "commonName : must match \"^[a-zA-Z0-9]{17,18}$\"");

                if (EnforceScope && !TokenInfo.MayActFor(pcid.Value))
                    return (HTTPStatusCode.Forbidden,
                            $"The given token is not authorized for the World Manufacturer Identifier '{pcid.Value.WMI}'!");

                return null;

            }

            #endregion

            // The provisioning signing authority, for which the specification states no rule -
            // and rightly: its certificates identify a service rather than a thing in ISO 15118.
            return null;

        }

        #endregion

        #region (private, static) TryParseISOVersion(Text, out XSDMsgDefNamespace)

        /// <summary>
        /// Read the generation out of a path segment.
        /// </summary>
        private static Boolean TryParseISOVersion(String Text, out XSD_MsgDefNamespace XSDMsgDefNamespace)
        {

            var isoVersion = XSD_MsgDefNamespace.TryParseISOVersion(Text);

            if (isoVersion.HasValue)
            {
                XSDMsgDefNamespace = isoVersion.Value;
                return true;
            }

            XSDMsgDefNamespace = default;
            return false;

        }

        #endregion

        #region (private) RespondWithCertificates(Request, Certificates)

        /// <summary>
        /// Answer with a certificates-only PKCS#7 structure, base64-encoded.
        /// </summary>
        private HTTPResponse RespondWithCertificates(HTTPRequest                  Request,
                                                     IEnumerable<PnCCertificate>  Certificates)
        {

            var builder = new HTTPResponse.Builder(Request) {
                              HTTPStatusCode            = HTTPStatusCode.OK,
                              Server                    = HTTPServer?.HTTPServerName,
                              Date                      = Timestamp.Now,
                              AccessControlAllowOrigin  = "*",
                              Content                   = Encoding.ASCII.GetBytes(
                                                              Pkcs7CertificateContainer.ToBase64(Certificates)
                                                          ),
                              Connection                = ConnectionType.KeepAlive
                          };

            builder.SetHeaderField("Content-Type",              CertsOnlyContentType);
            builder.SetHeaderField("Content-Transfer-Encoding", "base64");

            return builder.AsImmutable;

        }

        #endregion

        #region (private, static) Unarmour(Text)

        /// <summary>
        /// Strip PEM armour and line breaks from a certificate signing request.
        ///
        /// The interface takes base64 and a client that has one in a file has it with a header,
        /// a footer and line breaks. Reading both costs three lines and saves a support ticket.
        /// </summary>
        private static String Unarmour(String Text)

            => new (
                   [.. Text.Split('\n', '\r').
                            Where     (line => !line.TrimStart().StartsWith("-----")).
                            SelectMany(line => line.Trim())]
               );

        #endregion

    }


    /// <summary>
    /// CA distribution where the interface document puts it: at the root, with the authority as
    /// the first path segment and no prefix of any kind.
    ///
    /// RFC 7030 puts it under the same <c>/.well-known/est</c> prefix as enrollment, and the
    /// enrollment API serves it there too. This mount is what the OPCP document itself describes.
    /// </summary>
    public class ESTCACerts_HTTPAPI : AOPCPHTTPAPI
    {

        #region Properties

        /// <summary>
        /// The enrollment service whose authorities are published here.
        /// </summary>
        public EST_HTTPAPI EST { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Serve the CA distribution of the given enrollment service at an un-prefixed path.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server to attach to.</param>
        /// <param name="EST">The enrollment service whose authorities are to be published.</param>
        /// <param name="RootPath">An optional path prefix.</param>
        public ESTCACerts_HTTPAPI(HTTPServer   HTTPServer,
                                  EST_HTTPAPI  EST,
                                  HTTPPath?    RootPath   = null)

            : base(HTTPServer,
                   EST.AccessTokenValidator,
                   RootPath ?? EST_HTTPAPI.DefaultCACertsPath,
                   I18NString.Create("OPCP V2G PKI certification authority distribution"))

        {

            this.EST = EST ?? throw new ArgumentNullException(nameof(EST));

            AddHandler(
                HTTPMethod.GET,
                Route("{ca}/cacerts/{iso-version}/{algorithm}"),
                HTTPContentType.Application.JSON_UTF8,
                HTTPDelegate: this.EST.CACerts
            );

        }

        #endregion

    }

}
