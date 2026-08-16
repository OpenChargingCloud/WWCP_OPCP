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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// How an OPCP service decides whether to believe an access token.
    ///
    /// This is deliberately an abstraction rather than an implementation: a real ecosystem
    /// validates RS256 tokens against an identity provider's published keys, while the in-process
    /// ecosystem this library uses for its own tests signs and checks them itself. What the
    /// services above need from either is the same - a decoded, trusted set of claims, or a reason.
    /// </summary>
    public interface IAccessTokenValidator
    {

        /// <summary>
        /// Verify the given access token and return what it says its holder may do.
        /// </summary>
        /// <param name="Token">A JSON Web Token, without the "Bearer " prefix.</param>
        /// <param name="TokenInfo">The verified claims.</param>
        /// <param name="ErrorResponse">Why the token was not accepted.</param>
        Boolean TryValidate(String                                   Token,
                            [NotNullWhen(true)]  out OPCPTokenInfo?  TokenInfo,
                            [NotNullWhen(false)] out String?         ErrorResponse);

    }

}
