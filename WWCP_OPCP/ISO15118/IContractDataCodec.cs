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
    /// What a vehicle asked for when it plugged in.
    /// </summary>
    /// <param name="PCID">The vehicle, from the provisioning certificate it presented.</param>
    /// <param name="RootCertificateIds">
    /// The V2G roots the vehicle says it trusts. The pool answers with contract data anchored to
    /// one of them, because contract data anchored anywhere else is data this car cannot verify.
    /// </param>
    /// <param name="PrioritizedEMAIds">The contracts the vehicle would prefer, most preferred first.</param>
    /// <param name="MaximumContractCertificateChains">How many contracts the vehicle can take.</param>
    public sealed record CertificateInstallationRequest(PCID                 PCID,
                                                        IEnumerable<String>  RootCertificateIds,
                                                        IEnumerable<EMA_Id>  PrioritizedEMAIds,
                                                        Byte                 MaximumContractCertificateChains = 1);


    /// <summary>
    /// Where this library stops and ISO 15118 begins.
    ///
    /// OPCP transports three things it never looks inside: the request a vehicle makes when it
    /// plugs in, the response that goes back to it, and the signed contract data the contract
    /// provisioning service produces in between. All three are ISO 15118 structures, EXI- or
    /// XML-encoded and signed with XMLDSig, and nothing in the protocol this library implements
    /// needs to understand them - the pools move them, match them and store them by the metadata
    /// beside them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// So they stay behind this seam. <see cref="TestContractDataCodec"/> implements it with a
    /// container of this library's own, which is cryptographically real - the signatures are
    /// genuine ECDSA and are verified - and deliberately <b>not</b> the ISO 15118 wire format.
    /// It exists so that the whole Plug&amp;Charge lifecycle can be exercised end to end without
    /// an EXI codec.
    /// </para>
    /// <para>
    /// The real one is a matter of implementing this interface over
    /// <see href="https://github.com/OpenChargingCloud/WWCP_ISO15118">WWCP_ISO15118</see>, whose
    /// EXI codec and XMLDSig support are exactly what is missing. Nothing above this interface
    /// changes when that happens, which is the point of it being here.
    /// </para>
    /// </remarks>
    public interface IContractDataCodec
    {

        /// <summary>
        /// Read what a vehicle asked for.
        /// </summary>
        /// <param name="Request">The certificate installation request, as it arrived.</param>
        /// <param name="Decoded">What the vehicle asked for.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        Boolean TryDecodeInstallationRequest(Byte[]                                                Request,
                                             [NotNullWhen(true)]  out CertificateInstallationRequest?  Decoded,
                                             [NotNullWhen(false)] out String?                      ErrorResponse);

        /// <summary>
        /// Turn what the contract provisioning service signed into what goes back to the vehicle.
        /// </summary>
        /// <param name="SignedContractData">The signed contract data, as the pool stored it.</param>
        /// <param name="Response">The certificate installation response.</param>
        /// <param name="ErrorResponse">Why it could not be produced.</param>
        Boolean TryEncodeInstallationResponse(Byte[]                            SignedContractData,
                                              [NotNullWhen(true)]  out Byte[]?  Response,
                                              [NotNullWhen(false)] out String?  ErrorResponse);

        /// <summary>
        /// A response saying that nothing could be installed.
        ///
        /// The contract certificate pool answers a vehicle that has no contract with one of these
        /// rather than with an error, because a charging station relaying the answer speaks
        /// ISO 15118 and not HTTP.
        /// </summary>
        /// <param name="Reason">Why nothing could be installed.</param>
        Byte[] EncodeNegativeResponse(String Reason);

        /// <summary>
        /// Read the contract data out of what the contract provisioning service signed.
        ///
        /// The pool needs this to know what it is holding - which contract, whose certificate,
        /// valid until when - all of which it publishes when a manufacturer lists a vehicle's
        /// contracts, and none of which the request that stored it states separately.
        /// </summary>
        /// <param name="SignedContractData">The signed contract data.</param>
        /// <param name="ContractData">What it contains.</param>
        /// <param name="ErrorResponse">Why it could not be read.</param>
        Boolean TryReadSignedContractData(Byte[]                                 SignedContractData,
                                          [NotNullWhen(true)]  out ContractData? ContractData,
                                          [NotNullWhen(false)] out String?       ErrorResponse);

    }

}
