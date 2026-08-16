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

namespace cloud.charging.open.protocols.opcp.Tests.HTTP
{

    /// <summary>
    /// Composing an ecosystem's address, and the envelope every client call comes back in.
    /// </summary>
    [TestFixture]
    public class EndpointAndResponseTests
    {

        #region The_URI_shape_of_the_specification_is_composed(Region, Stage, Expected)

        /// <summary>
        /// https://{region}.{stage}.{domain} - the part in front of the version, service and
        /// object that every path in the specification already carries.
        /// </summary>
        [TestCase("eu", "plugncharge-qa",   "https://eu.plugncharge-qa.hubject.com")]
        [TestCase("eu", "plugncharge-test", "https://eu.plugncharge-test.hubject.com")]
        [TestCase("eu", "plugncharge",      "https://eu.plugncharge.hubject.com")]
        [TestCase("us", "plugncharge",      "https://us.plugncharge.hubject.com")]
        public void The_URI_shape_of_the_specification_is_composed(String Region, String Stage, String Expected)
        {

            var config = OPCPEndpointConfig.Hubject(Region, Stage);

            Assert.Multiple(() => {
                Assert.That(config.BaseURL. ToString(),  Is.EqualTo(Expected));
                Assert.That(config.Audience.ToString(),  Is.EqualTo(Expected), "The audience is the deployment itself.");
                Assert.That(config.ToString(),           Is.EqualTo(Expected));
            });

        }

        #endregion

        #region The_token_endpoint_is_a_separate_host_without_the_stage()

        /// <summary>
        /// The example token of accessToken.v1.json was issued by
        /// https://auth.eu.plugncharge.hubject.com/ for the audience
        /// https://eu.plugncharge-qa.hubject.com - a different host, and one that does not
        /// carry the stage the audience does.
        /// </summary>
        [Test]
        public void The_token_endpoint_is_a_separate_host_without_the_stage()
        {

            var qa = OPCPEndpointConfig.EU_QA;

            Assert.Multiple(() => {
                Assert.That(qa.TokenEndpoint.ToString(),  Is.EqualTo("https://auth.eu.plugncharge.hubject.com/oauth/token"));
                Assert.That(qa.Audience.     ToString(),  Is.EqualTo("https://eu.plugncharge-qa.hubject.com"));
                Assert.That(OPCPEndpointConfig.US_Test.TokenEndpoint.ToString(),
                            Is.EqualTo("https://auth.us.plugncharge.hubject.com/oauth/token"));
            });

        }

        #endregion

        #region Any_other_deployment_can_be_addressed()

        /// <summary>
        /// Every interface document ships an empty servers list, so no address is more official
        /// than another. An ecosystem of a different shape entirely has to be reachable.
        /// </summary>
        [Test]
        public void Any_other_deployment_can_be_addressed()
        {

            var ours = new OPCPEndpointConfig(URL.Parse("https://pnc.example.org:8443/opcp/"));

            Assert.Multiple(() => {
                Assert.That(ours.BaseURL.      ToString(),  Is.EqualTo("https://pnc.example.org:8443/opcp"), "A trailing slash is trimmed.");
                Assert.That(ours.TokenEndpoint.ToString(),  Is.EqualTo("https://pnc.example.org:8443/opcp/oauth/token"));
                Assert.That(ours.Audience.     ToString(),  Is.EqualTo("https://pnc.example.org:8443/opcp"));
            });

        }

        #endregion

        #region An_incomplete_configuration_is_refused(Region, Stage, Domain)

        [TestCase("",   "plugncharge", "hubject.com")]
        [TestCase("eu", "",            "hubject.com")]
        [TestCase("eu", "plugncharge", "")]
        public void An_incomplete_configuration_is_refused(String Region, String Stage, String Domain)
        {

            Assert.That(() => OPCPEndpointConfig.Create(Region, Stage, Domain),
                        Throws.ArgumentException);

        }

        #endregion

        #region A_successful_response_carries_its_payload()

        [Test]
        public void A_successful_response_carries_its_payload()
        {

            var response = OPCPResponse<String>.Success("the signed contract data",
                                                        HTTPStatusCode.Created,
                                                        Runtime: TimeSpan.FromMilliseconds(42));

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,          Is.True);
                Assert.That(response.HasError,           Is.False);
                Assert.That(response.Data,               Is.EqualTo("the signed contract data"));
                Assert.That(response.Error,              Is.Null);
                Assert.That(response.TraceId,            Is.Null);
                Assert.That(response.HTTPStatusCode,     Is.EqualTo(HTTPStatusCode.Created));
                Assert.That(response.GetDataOrThrow(),   Is.EqualTo("the signed contract data"));
                Assert.That(response.EventTrackingId.IsNotNullOrEmpty,  Is.True);
            });

        }

        #endregion

        #region A_refused_response_carries_the_operators_own_words()

        [Test]
        public void A_refused_response_carries_the_operators_own_words()
        {

            var traceId   = Trace_Id.NewRandom();
            var response  = OPCPResponse<String>.Failed(new OPCPError([ "Contract or Vehicle not found." ], traceId),
                                                        HTTPStatusCode.NotFound);

            Assert.Multiple(() => {
                Assert.That(response.IsSuccess,       Is.False);
                Assert.That(response.HasError,        Is.True);
                Assert.That(response.Data,            Is.Null);
                Assert.That(response.TraceId,         Is.EqualTo(traceId));
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
                Assert.That(response.ToString(),      Does.Contain("Contract or Vehicle not found."));

                var exception = Assert.Throws<OPCPErrorException>(() => response.GetDataOrThrow());
                Assert.That(exception!.Message,       Does.Contain("Contract or Vehicle not found."));
                Assert.That(exception.Response,       Is.SameAs(response));
            });

        }

        #endregion

        #region A_body_less_operation_still_reports_its_outcome()

        /// <summary>
        /// Deleting a provisioning certificate, or marking a contract as the default for offline
        /// installation, answers with a status and nothing else.
        /// </summary>
        [Test]
        public void A_body_less_operation_still_reports_its_outcome()
        {

            var ok      = OPCPResponse.Success();
            var refused = OPCPResponse.Failed(OPCPError.Create("The OEM provisioning certificate with the given PCID is not available."),
                                              HTTPStatusCode.NotFound);

            Assert.Multiple(() => {
                Assert.That(ok.IsSuccess,            Is.True);
                Assert.That(ok.HTTPStatusCode,       Is.EqualTo(HTTPStatusCode.OK));

                Assert.That(refused.IsSuccess,       Is.False);
                Assert.That(refused.TraceId,         Is.Not.Null, "Create() always mints a trace to quote.");
                Assert.That(refused.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.NotFound));
            });

        }

        #endregion

        #region The_enrollment_media_types_resolve_to_one_instance_each()

        /// <summary>
        /// Registering these once means a request or response naming one of them parses to the
        /// very same content type, which is what lets the EST client and API compare them.
        /// </summary>
        [Test]
        public void The_enrollment_media_types_resolve_to_one_instance_each()
        {

            OPCPContentTypes.Touch();

            Assert.Multiple(() => {

                Assert.That(OPCPContentTypes.PKCS10.      ToString(),  Does.StartWith("application/pkcs10"));
                Assert.That(OPCPContentTypes.PKCS7Mime.   ToString(),  Does.StartWith("application/pkcs7-mime"));
                Assert.That(OPCPContentTypes.OCSPRequest. ToString(),  Does.StartWith("application/ocsp-request"));
                Assert.That(OPCPContentTypes.OCSPResponse.ToString(),  Does.StartWith("application/ocsp-response"));

                Assert.That(HTTPContentType.TryParse("application/pkcs10", out var pkcs10),  Is.True);
                Assert.That(pkcs10,  Is.SameAs(OPCPContentTypes.PKCS10));

            });

        }

        #endregion

    }

}
