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

#endregion

namespace cloud.charging.open.protocols.opcp.Tests.Infrastructure
{

    /// <summary>
    /// The golden vectors under "Vectors/", copied next to the test assembly at build time.
    /// Each carries a "_source" naming where its values came from - see Vectors/README.md.
    /// </summary>
    public static class Vectors
    {

        #region Load(FileName)

        /// <summary>
        /// Load one golden vector.
        /// </summary>
        /// <param name="FileName">The file name of the vector, e.g. "rcp-v2g-root-ca-g2.json".</param>
        public static JObject Load(String FileName)
        {

            var path = Path.Combine(AppContext.BaseDirectory, "Vectors", FileName);

            if (!File.Exists(path))
                throw new FileNotFoundException($"The test vector '{FileName}' was not copied to the output directory!", path);

            return JObject.Parse(File.ReadAllText(path));

        }

        #endregion

        #region GetString(Vector, PropertyName)

        /// <summary>
        /// Read a string property of a vector, failing loudly when it is absent: a vector
        /// missing the value a test is about would otherwise let the test pass vacuously.
        /// </summary>
        /// <param name="Vector">A loaded vector.</param>
        /// <param name="PropertyName">The name of the property.</param>
        public static String GetString(JObject Vector, String PropertyName)

            => Vector.Value<String>(PropertyName)
                   ?? throw new KeyNotFoundException($"The test vector has no '{PropertyName}' property!");

        #endregion

    }

}
