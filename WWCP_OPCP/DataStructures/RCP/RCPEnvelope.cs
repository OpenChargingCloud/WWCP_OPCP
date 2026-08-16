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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The wrappers the Root Certificate Pool puts around its answers.
    ///
    /// A single root comes back inside a <c>RootResponse</c> object, and a list of them inside a
    /// <c>RootCertificateCollection</c> containing a <c>rootCertificates</c> array. Both are
    /// PascalCase in an otherwise camelCase protocol - the specification's own naming rules note
    /// that version 1 has exceptions, and these are two of them.
    ///
    /// Keeping the wrapping here rather than in the data structures means the clients and the API
    /// hand each other root certificates, and the one place that knows about these envelopes is
    /// the one place that has to.
    /// </summary>
    public static class RCPEnvelope
    {

        #region Data

        /// <summary>The property a single root certificate is returned under.</summary>
        public const String RootResponse               = "RootResponse";

        /// <summary>The property a collection of root certificates is returned under.</summary>
        public const String RootCertificateCollection  = "RootCertificateCollection";

        /// <summary>The array within that collection.</summary>
        public const String RootCertificates           = "rootCertificates";

        #endregion


        #region WrapOne (RootCertificate, CustomRootCertificateSerializer = null)

        /// <summary>
        /// Wrap one root certificate as getRootCert returns it.
        /// </summary>
        /// <param name="RootCertificate">A root certificate.</param>
        /// <param name="CustomRootCertificateSerializer">A delegate to serialize custom root certificates.</param>
        public static JObject WrapOne(RootCertificate                                   RootCertificate,
                                      CustomJObjectSerializerDelegate<RootCertificate>? CustomRootCertificateSerializer = null)

            => new (
                   new JProperty(RootResponse,
                                 RootCertificate.ToJSON(CustomRootCertificateSerializer))
               );

        #endregion

        #region WrapMany(RootCertificates, CustomRootCertificateSerializer = null)

        /// <summary>
        /// Wrap a collection of root certificates as getAllRootCerts returns it.
        /// </summary>
        /// <param name="RootCertificates">An enumeration of root certificates.</param>
        /// <param name="CustomRootCertificateSerializer">A delegate to serialize custom root certificates.</param>
        public static JObject WrapMany(IEnumerable<RootCertificate>                      RootCertificates,
                                       CustomJObjectSerializerDelegate<RootCertificate>? CustomRootCertificateSerializer = null)

            => new (
                   new JProperty(RootCertificateCollection,
                                 new JObject(
                                     new JProperty(RCPEnvelope.RootCertificates,
                                                   new JArray(RootCertificates.Select(rootCertificate => rootCertificate.ToJSON(CustomRootCertificateSerializer))))
                                 ))
               );

        #endregion


        #region TryUnwrapOne (JSON, out RootCertificate, out ErrorResponse)

        /// <summary>
        /// Read the single root certificate out of a getRootCert response.
        /// </summary>
        /// <param name="JSON">The JSON body of the response.</param>
        /// <param name="RootCertificate">The parsed root certificate.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryUnwrapOne(JObject               JSON,
                                           out RootCertificate?  RootCertificate,
                                           out String?           ErrorResponse)
        {

            RootCertificate  = null;
            ErrorResponse    = null;

            // A pool that answered with the bare object rather than the envelope is still
            // answering; there is nothing to gain by refusing to understand it.
            var inner = JSON[RootResponse] as JObject ?? JSON;

            if (!inner.HasValues)
            {
                ErrorResponse = $"The response carries no '{RootResponse}' object!";
                return false;
            }

            return opcp.RootCertificate.TryParse(inner, out RootCertificate, out ErrorResponse);

        }

        #endregion

        #region TryUnwrapMany(JSON, out Certificates, out ErrorResponse)

        /// <summary>
        /// Read the root certificates out of a getAllRootCerts response.
        /// </summary>
        /// <param name="JSON">The JSON body of the response.</param>
        /// <param name="Certificates">The parsed root certificates.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryUnwrapMany(JObject                 JSON,
                                            out RootCertificate[]?  Certificates,
                                            out String?             ErrorResponse)
        {

            Certificates   = null;
            ErrorResponse  = null;

            var array = (JSON[RootCertificateCollection] as JObject)?[RootCertificates] as JArray
                            ?? JSON[RootCertificates] as JArray;

            if (array is null)
            {
                ErrorResponse = $"The response carries no '{RootCertificateCollection}.{RootCertificates}' array!";
                return false;
            }

            var parsed = new List<RootCertificate>();

            foreach (var item in array)
            {

                if (item is not JObject json)
                {
                    ErrorResponse = "The list of root certificates contains something that is not an object!";
                    return false;
                }

                if (!RootCertificate.TryParse(json, out var rootCertificate, out ErrorResponse))
                    return false;

                parsed.Add(rootCertificate);

            }

            Certificates = [.. parsed];
            return true;

        }

        #endregion

    }

}
