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

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// Where an OPCP client gets the bearer token for its next request.
    /// </summary>
    public interface IAccessTokenProvider
    {

        /// <summary>
        /// Return a token that is valid now, obtaining or renewing one if necessary.
        /// </summary>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        Task<String> GetAccessTokenAsync(CancellationToken CancellationToken = default);

    }


    /// <summary>
    /// A token somebody else obtained.
    ///
    /// For the case where credentials live outside this process entirely - a token pasted into a
    /// configuration file, or minted by a sidecar that owns the client secret.
    /// </summary>
    public class StaticAccessTokenProvider : IAccessTokenProvider
    {

        #region Properties

        /// <summary>
        /// The token.
        /// </summary>
        public String  AccessToken    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new provider of a fixed access token.
        /// </summary>
        /// <param name="AccessToken">A JSON Web Token.</param>
        public StaticAccessTokenProvider(String AccessToken)
        {

            if (AccessToken.IsNullOrEmpty())
                throw new ArgumentException("The given access token must not be null or empty!", nameof(AccessToken));

            this.AccessToken = AccessToken;

        }

        #endregion


        /// <summary>
        /// Return the token.
        /// </summary>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public Task<String> GetAccessTokenAsync(CancellationToken CancellationToken = default)

            => Task.FromResult(AccessToken);


        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => "a fixed access token";

    }

}
