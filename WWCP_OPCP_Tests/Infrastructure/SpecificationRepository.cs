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
    /// Access to the OPCP specification, checked out as a git submodule under "libs/OPCP".
    ///
    /// Tests read the specification directly rather than through a copy, so that updating
    /// the submodule is what makes them fail. The submodule may legitimately be absent -
    /// a shallow clone without "--recurse-submodules" - in which case the tests depending
    /// on it are ignored rather than failed.
    /// </summary>
    public static class SpecificationRepository
    {

        #region Data

        /// <summary>
        /// The "libs/OPCP" directory of the specification submodule, or null when it is not checked out.
        /// </summary>
        public static DirectoryInfo?  RootDirectory         { get; }

        /// <summary>
        /// The release directories ("OPCP-1.0.0", ...) present in the specification submodule.
        /// </summary>
        public static DirectoryInfo[] ReleaseDirectories    { get; }

        /// <summary>
        /// The "reference" directory holding the OpenAPI documents of the implemented release,
        /// or null when the submodule is not checked out or does not carry that release.
        /// </summary>
        public static DirectoryInfo?  ReferenceDirectory    { get; }

        #endregion

        #region Constructor(s)

        static SpecificationRepository()
        {

            RootDirectory       = FindRootDirectory();

            ReleaseDirectories  = RootDirectory?.GetDirectories("OPCP-*") ?? [];

            var reference       = RootDirectory is not null
                                      ? new DirectoryInfo(Path.Combine(RootDirectory.FullName,
                                                                       $"OPCP-{OPCPSpecification.Release}",
                                                                       "reference"))
                                      : null;

            ReferenceDirectory  = reference?.Exists == true
                                      ? reference
                                      : null;

        }

        #endregion


        #region (private, static) FindRootDirectory()

        /// <summary>
        /// Walk up from the test assembly towards the repository root, looking for "libs/OPCP".
        /// The number of directories between the two depends on the build configuration and
        /// target framework, so it is searched for rather than counted.
        /// </summary>
        private static DirectoryInfo? FindRootDirectory()
        {

            var directory = new DirectoryInfo(AppContext.BaseDirectory);

            while (directory is not null)
            {

                var candidate = new DirectoryInfo(Path.Combine(directory.FullName, "libs", "OPCP"));

                if (candidate.Exists)
                    return candidate;

                directory = directory.Parent;

            }

            return null;

        }

        #endregion

        #region (static) ReadDocument (FileName)

        /// <summary>
        /// Read one OpenAPI document of the implemented release.
        /// </summary>
        /// <param name="FileName">The file name of the document, e.g. "rcp.v1.json".</param>
        public static JObject ReadDocument(String FileName)
        {

            if (ReferenceDirectory is null)
                throw new InvalidOperationException("The OPCP specification submodule is not checked out!");

            return JObject.Parse(File.ReadAllText(Path.Combine(ReferenceDirectory.FullName, FileName)));

        }

        #endregion

        #region (static) IgnoreWhenUnavailable()

        /// <summary>
        /// Ignore the current test when the specification submodule is not checked out.
        /// </summary>
        public static void IgnoreWhenUnavailable()
        {

            if (ReferenceDirectory is null)
                Assert.Ignore("The OPCP specification submodule is not checked out: " +
                              "run 'git submodule update --init --recursive'.");

        }

        #endregion

    }

}
