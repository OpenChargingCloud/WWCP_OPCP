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

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// How a token is obtained. The provider owns when to ask; this is what it asks.
    /// </summary>
    /// <param name="CancellationToken">A token to cancel the request.</param>
    public delegate Task<AccessTokenResponse> AccessTokenRequestDelegate(CancellationToken CancellationToken);


    /// <summary>
    /// Holds an OPCP access token and renews it before it expires.
    ///
    /// OPCP tokens last 24 hours, so fetching one per request would be absurd and fetching one per
    /// process would eventually fail mid-run. This keeps the current one until shortly before it
    /// lapses, and lets exactly one caller renew it while the others wait for that result rather
    /// than starting renewals of their own.
    /// </summary>
    /// <remarks>
    /// Where the token comes from is injected rather than built in: the caching and renewal logic
    /// is worth testing on its own, and the same provider serves a real token endpoint and an
    /// in-process ecosystem without knowing the difference.
    /// </remarks>
    public class ClientCredentialsTokenProvider : IAccessTokenProvider, IDisposable
    {

        #region Data

        private readonly AccessTokenRequestDelegate  requestToken;
        private readonly SemaphoreSlim               renewalLock   = new (1, 1);
        private          AccessTokenResponse?        currentToken;

        /// <summary>
        /// How long before expiry a token is renewed. A token that lapses while a request is
        /// still in flight is refused on arrival, so renewal happens with room to spare.
        /// </summary>
        public static readonly TimeSpan DefaultSafetyMargin = TimeSpan.FromMinutes(5);

        #endregion

        #region Properties

        /// <summary>
        /// How long before expiry this provider renews.
        /// </summary>
        public TimeSpan              SafetyMargin    { get; }

        /// <summary>
        /// The token currently held, if any. Reading it does not obtain one.
        /// </summary>
        public AccessTokenResponse?  CurrentToken
            => currentToken;

        /// <summary>
        /// How many times this provider has obtained a token.
        /// </summary>
        public UInt64                Renewals        { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new caching access token provider.
        /// </summary>
        /// <param name="RequestToken">How to obtain a token.</param>
        /// <param name="SafetyMargin">An optional margin before expiry to renew within.</param>
        /// <param name="InitialToken">An optional token already held.</param>
        public ClientCredentialsTokenProvider(AccessTokenRequestDelegate  RequestToken,
                                              TimeSpan?                   SafetyMargin   = null,
                                              AccessTokenResponse?        InitialToken   = null)
        {

            this.requestToken  = RequestToken ?? throw new ArgumentNullException(nameof(RequestToken));
            this.SafetyMargin  = SafetyMargin ?? DefaultSafetyMargin;
            this.currentToken  = InitialToken;

        }

        #endregion


        #region GetAccessTokenAsync(CancellationToken = default)

        /// <summary>
        /// Return a token that is valid now, renewing it first if it is not.
        /// </summary>
        /// <param name="CancellationToken">An optional token to cancel this request.</param>
        public async Task<String> GetAccessTokenAsync(CancellationToken CancellationToken = default)
        {

            var token = currentToken;

            if (token is not null && token.IsValidAt(DateTimeOffset.UtcNow, SafetyMargin))
                return token.AccessToken;

            await renewalLock.WaitAsync(CancellationToken).ConfigureAwait(false);

            try
            {

                // Another caller may have renewed while this one waited for the lock.
                token = currentToken;

                if (token is not null && token.IsValidAt(DateTimeOffset.UtcNow, SafetyMargin))
                    return token.AccessToken;

                var renewed = await requestToken(CancellationToken).ConfigureAwait(false);

                currentToken  = renewed;
                Renewals++;

                return renewed.AccessToken;

            }
            finally
            {
                renewalLock.Release();
            }

        }

        #endregion

        #region Invalidate()

        /// <summary>
        /// Discard the token currently held, so that the next request obtains a new one.
        ///
        /// For when a service answers 401 to a token this provider still believed in - a token
        /// can stop being honoured before it stops being unexpired.
        /// </summary>
        public void Invalidate()
        {
            currentToken = null;
        }

        #endregion

        #region Dispose()

        /// <summary>
        /// Dispose this provider.
        /// </summary>
        public void Dispose()
        {
            renewalLock.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => currentToken is null
                   ? "no access token yet"
                   : $"an access token expiring {currentToken.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC ({Renewals} renewals)";

        #endregion

    }

}
