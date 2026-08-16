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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The media types OPCP speaks beyond JSON.
    ///
    /// Almost all of OPCP is <c>application/json</c>, which Hermod already knows. Enrollment is
    /// the exception: a certificate signing request goes up as PKCS#10 and the issued chain comes
    /// back as a certificates-only PKCS#7, both base64-encoded. Revocation checking adds two more.
    /// </summary>
    public static class OPCPContentTypes
    {

        #region Data

        /// <summary>
        /// A PKCS#10 certificate signing request, base64-encoded - what simpleenroll accepts.
        /// </summary>
        public static HTTPContentType  PKCS10          { get; }

        /// <summary>
        /// A PKCS#7 structure carrying certificates and nothing else - what simpleenroll and
        /// cacerts return. RFC 7030 asks for the '-mime' spelling with an smime-type parameter;
        /// the OPCP document names the bare form as well, so both are here.
        /// </summary>
        public static HTTPContentType  PKCS7           { get; }

        /// <summary>
        /// A certificates-only PKCS#7, spelled as RFC 7030 spells it.
        /// </summary>
        public static HTTPContentType  PKCS7Mime       { get; }

        /// <summary>
        /// An OCSP request (RFC 6960). The V2G PKI's responders take these unauthenticated.
        /// </summary>
        public static HTTPContentType  OCSPRequest     { get; }

        /// <summary>
        /// An OCSP response (RFC 6960).
        /// </summary>
        public static HTTPContentType  OCSPResponse    { get; }

        #endregion

        #region Constructor(s)

        static OPCPContentTypes()
        {

            // Hermod registers a media type it has not seen the first time one is parsed,
            // so parsing here is what puts these into its lookup - after this, a request or
            // response naming one of them resolves to the same instance.
            PKCS10        = Register("application/pkcs10");
            PKCS7         = Register("application/pkcs7");
            PKCS7Mime     = Register("application/pkcs7-mime");
            OCSPRequest   = Register("application/ocsp-request");
            OCSPResponse  = Register("application/ocsp-response");

        }

        #endregion


        #region (private, static) Register(MediaType)

        private static HTTPContentType Register(String MediaType)

            => HTTPContentType.TryParse(MediaType, out var contentType)
                   ? contentType
                   : throw new InvalidOperationException($"The media type '{MediaType}' could not be registered!");

        #endregion

        #region (static) Touch()

        /// <summary>
        /// Ensure the media types above are registered with Hermod.
        ///
        /// A static constructor runs when the class is first touched, which for a class of
        /// constants may be later than the first request that needs one of them to already be
        /// known. Calling this from an OPCP client or API as it starts removes that ordering
        /// question entirely.
        /// </summary>
        public static void Touch()
        { }

        #endregion

    }

}
