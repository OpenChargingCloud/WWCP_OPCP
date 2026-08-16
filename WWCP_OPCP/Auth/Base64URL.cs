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

#endregion

namespace cloud.charging.open.protocols.opcp
{

    /// <summary>
    /// The unpadded, URL-safe base64 of RFC 4648 §5, which is what the three parts of a
    /// JSON Web Token are encoded in.
    /// </summary>
    public static class Base64URL
    {

        #region Encode(Bytes)

        /// <summary>
        /// Encode the given bytes as unpadded URL-safe base64.
        /// </summary>
        /// <param name="Bytes">The bytes to encode.</param>
        public static String Encode(Byte[] Bytes)

            => Convert.ToBase64String(Bytes).
                       TrimEnd('=').
                       Replace('+', '-').
                       Replace('/', '_');

        #endregion

        #region Encode(Text)

        /// <summary>
        /// Encode the given text as unpadded URL-safe base64.
        /// </summary>
        /// <param name="Text">The text to encode.</param>
        public static String Encode(String Text)

            => Encode(Encoding.UTF8.GetBytes(Text));

        #endregion

        #region TryDecode(Text, out Bytes)

        /// <summary>
        /// Try to decode the given unpadded URL-safe base64.
        /// </summary>
        /// <param name="Text">The text to decode.</param>
        /// <param name="Bytes">The decoded bytes.</param>
        public static Boolean TryDecode(String Text, out Byte[] Bytes)
        {

            try
            {

                var padded = Text.Replace('-', '+').
                                  Replace('_', '/');

                // Base64 needs its length to be a multiple of four; the URL-safe form drops
                // the padding that would have provided it.
                padded += (padded.Length % 4) switch {
                              2  => "==",
                              3  => "=",
                              0  => "",
                              _  => null   // a remainder of one is not a valid encoding
                          };

                Bytes = Convert.FromBase64String(padded);
                return true;

            }
            catch
            {
                Bytes = [];
                return false;
            }

        }

        #endregion

        #region TryDecodeUTF8(Text, out Decoded)

        /// <summary>
        /// Try to decode the given unpadded URL-safe base64 as UTF-8 text.
        /// </summary>
        /// <param name="Text">The text to decode.</param>
        /// <param name="Decoded">The decoded text.</param>
        public static Boolean TryDecodeUTF8(String Text, out String Decoded)
        {

            if (TryDecode(Text, out var bytes))
            {
                try
                {
                    Decoded = Encoding.UTF8.GetString(bytes);
                    return true;
                }
                catch
                { }
            }

            Decoded = "";
            return false;

        }

        #endregion

    }

}
