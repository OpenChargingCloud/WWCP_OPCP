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
    /// Extension methods for ISO 15118 message definition namespaces.
    /// </summary>
    public static class XSD_MsgDefNamespaceExtensions
    {

        /// <summary>
        /// Indicates whether this message definition namespace is null or empty.
        /// </summary>
        /// <param name="XSD_MsgDefNamespace">A message definition namespace.</param>
        public static Boolean IsNullOrEmpty(this XSD_MsgDefNamespace? XSD_MsgDefNamespace)
            => !XSD_MsgDefNamespace.HasValue || XSD_MsgDefNamespace.Value.IsNullOrEmpty;

        /// <summary>
        /// Indicates whether this message definition namespace is NOT null or empty.
        /// </summary>
        /// <param name="XSD_MsgDefNamespace">A message definition namespace.</param>
        public static Boolean IsNotNullOrEmpty(this XSD_MsgDefNamespace? XSD_MsgDefNamespace)
            => XSD_MsgDefNamespace.HasValue && XSD_MsgDefNamespace.Value.IsNotNullOrEmpty;

    }


    /// <summary>
    /// The ISO 15118 message definition namespace a request or a stored certificate belongs to.
    /// It appears on nearly every OPCP operation, and it is how the ecosystem tells the two
    /// generations of ISO 15118 apart.
    /// </summary>
    /// <remarks>
    /// ISO 15118-20 has two spellings in OPCP, and they are not a typo one can pick a winner for:
    /// the root certificate pool and the webhook payloads say <c>urn:iso:15118:20:2022:MsgDef</c>,
    /// while the enrollment service's query parameter says <c>urn:iso:15118:20:2020:MsgDef</c>.
    /// Both are registered, both answer true to <see cref="IsISO15118_20"/>, and each is emitted
    /// where the specification asks for it.
    /// </remarks>
    public readonly struct XSD_MsgDefNamespace : IId,
                                                 IEquatable<XSD_MsgDefNamespace>,
                                                 IComparable<XSD_MsgDefNamespace>
    {

        #region Data

        private readonly static Dictionary<String, XSD_MsgDefNamespace>  lookup = new (StringComparer.OrdinalIgnoreCase);
        private readonly        String                                   InternalId;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this message definition namespace is null or empty.
        /// </summary>
        public readonly  Boolean                           IsNullOrEmpty
            => InternalId.IsNullOrEmpty();

        /// <summary>
        /// Indicates whether this message definition namespace is NOT null or empty.
        /// </summary>
        public readonly  Boolean                           IsNotNullOrEmpty
            => InternalId.IsNotNullOrEmpty();

        /// <summary>
        /// The length of the message definition namespace.
        /// </summary>
        public readonly  UInt64                            Length
            => (UInt64) (InternalId?.Length ?? 0);

        /// <summary>
        /// Whether this is the ISO 15118-2 namespace.
        /// </summary>
        public readonly  Boolean                           IsISO15118_2
            => Equals(ISO15118_2);

        /// <summary>
        /// Whether this is one of the two ISO 15118-20 namespaces.
        /// </summary>
        public readonly  Boolean                           IsISO15118_20
            => Equals(ISO15118_20) || Equals(ISO15118_20_2020);

        /// <summary>
        /// All registered message definition namespaces.
        /// </summary>
        public static    IEnumerable<XSD_MsgDefNamespace>  All
            => lookup.Values;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new message definition namespace based on the given text.
        /// </summary>
        /// <param name="Text">The text representation of a message definition namespace.</param>
        private XSD_MsgDefNamespace(String Text)
        {
            this.InternalId = Text;
        }

        #endregion


        #region (private static) Register(Text)

        private static XSD_MsgDefNamespace Register(String Text)

            => lookup.AddAndReturnValue(
                   Text,
                   new XSD_MsgDefNamespace(Text)
               );

        #endregion


        #region (static) Parse   (Text)

        /// <summary>
        /// Parse the given string as a message definition namespace.
        /// </summary>
        /// <param name="Text">A text representation of a message definition namespace.</param>
        public static XSD_MsgDefNamespace Parse(String Text)
        {

            if (TryParse(Text, out var xsdMsgDefNamespace))
                return xsdMsgDefNamespace;

            throw new ArgumentException($"Invalid text representation of a message definition namespace: '{Text}'!",
                                        nameof(Text));

        }

        #endregion

        #region (static) TryParse(Text)

        /// <summary>
        /// Try to parse the given text as a message definition namespace.
        /// </summary>
        /// <param name="Text">A text representation of a message definition namespace.</param>
        public static XSD_MsgDefNamespace? TryParse(String Text)
        {

            if (TryParse(Text, out var xsdMsgDefNamespace))
                return xsdMsgDefNamespace;

            return null;

        }

        #endregion

        #region (static) TryParse(Text, out XSDMsgDefNamespace)

        /// <summary>
        /// Try to parse the given text as a message definition namespace.
        /// </summary>
        /// <param name="Text">A text representation of a message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace">The parsed message definition namespace.</param>
        public static Boolean TryParse(String Text, out XSD_MsgDefNamespace XSDMsgDefNamespace)
        {

            Text = Text.Trim();

            if (Text.IsNotNullOrEmpty())
            {

                if (!lookup.TryGetValue(Text, out XSDMsgDefNamespace))
                    XSDMsgDefNamespace = Register(Text);

                return true;

            }

            XSDMsgDefNamespace = default;
            return false;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this message definition namespace.
        /// </summary>
        public XSD_MsgDefNamespace Clone()

            => new (
                   InternalId.CloneString()
               );

        #endregion


        #region Static definitions

        /// <summary>
        /// ISO 15118-2:2014 - the generation OPCP is built around, and the default
        /// of every operation that takes a namespace.
        /// </summary>
        public static XSD_MsgDefNamespace  ISO15118_2        { get; }
            = Register("urn:iso:15118:2:2013:MsgDef");

        /// <summary>
        /// ISO 15118-20:2022, as spelled by the root certificate pool and the webhook payloads.
        /// </summary>
        public static XSD_MsgDefNamespace  ISO15118_20       { get; }
            = Register("urn:iso:15118:20:2022:MsgDef");

        /// <summary>
        /// ISO 15118-20, as spelled by the enrollment service's query parameter. The same
        /// generation as <see cref="ISO15118_20"/>, written differently by the specification.
        /// </summary>
        public static XSD_MsgDefNamespace  ISO15118_20_2020  { get; }
            = Register("urn:iso:15118:20:2020:MsgDef");

        #endregion


        #region ISO version path segments

        /// <summary>
        /// Read the generation as the enrollment service writes it in a path.
        ///
        /// That service names the same two generations twice over: <c>ISO15118-2</c> and
        /// <c>ISO15118-20</c> in the path, the namespaces above in the query string beside it.
        /// Both forms mean the same thing and are read into the same values.
        /// </summary>
        /// <param name="Text">A path segment, e.g. "ISO15118-2".</param>
        public static XSD_MsgDefNamespace? TryParseISOVersion(String Text)
        {

            var text = Text.Trim();

            if (text.Equals("ISO15118-2",  StringComparison.OrdinalIgnoreCase))
                return ISO15118_2;

            if (text.Equals("ISO15118-20", StringComparison.OrdinalIgnoreCase))
                return ISO15118_20;

            // The namespaces themselves are accepted here too: a caller that has one to hand
            // should not have to translate it before putting it in a path.
            return TryParse(text);

        }

        /// <summary>
        /// Write this generation as the enrollment service writes it in a path.
        /// </summary>
        public readonly String ToISOVersion()

            => IsISO15118_20
                   ? "ISO15118-20"
                   : "ISO15118-2";

        #endregion


        #region Operator overloading

        #region Operator == (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                           XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => XSDMsgDefNamespace1.Equals(XSDMsgDefNamespace2);

        #endregion

        #region Operator != (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                           XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => !XSDMsgDefNamespace1.Equals(XSDMsgDefNamespace2);

        #endregion

        #region Operator <  (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                          XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => XSDMsgDefNamespace1.CompareTo(XSDMsgDefNamespace2) < 0;

        #endregion

        #region Operator <= (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                           XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => XSDMsgDefNamespace1.CompareTo(XSDMsgDefNamespace2) <= 0;

        #endregion

        #region Operator >  (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                          XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => XSDMsgDefNamespace1.CompareTo(XSDMsgDefNamespace2) > 0;

        #endregion

        #region Operator >= (XSDMsgDefNamespace1, XSDMsgDefNamespace2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="XSDMsgDefNamespace1">A message definition namespace.</param>
        /// <param name="XSDMsgDefNamespace2">Another message definition namespace.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (XSD_MsgDefNamespace XSDMsgDefNamespace1,
                                           XSD_MsgDefNamespace XSDMsgDefNamespace2)

            => XSDMsgDefNamespace1.CompareTo(XSDMsgDefNamespace2) >= 0;

        #endregion

        #endregion

        #region IComparable<XSDMsgDefNamespace> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two message definition namespaces.
        /// </summary>
        /// <param name="Object">A message definition namespace to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is XSD_MsgDefNamespace xsdMsgDefNamespace
                   ? CompareTo(xsdMsgDefNamespace)
                   : throw new ArgumentException("The given object is not a message definition namespace!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(XSDMsgDefNamespace)

        /// <summary>
        /// Compares two message definition namespaces.
        /// </summary>
        /// <param name="XSDMsgDefNamespace">A message definition namespace to compare with.</param>
        public Int32 CompareTo(XSD_MsgDefNamespace XSDMsgDefNamespace)

            => String.Compare(InternalId,
                              XSDMsgDefNamespace.InternalId,
                              StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region IEquatable<XSDMsgDefNamespace> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two message definition namespaces for equality.
        /// </summary>
        /// <param name="Object">A message definition namespace to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is XSD_MsgDefNamespace xsdMsgDefNamespace &&
                   Equals(xsdMsgDefNamespace);

        #endregion

        #region Equals(XSDMsgDefNamespace)

        /// <summary>
        /// Compares two message definition namespaces for equality.
        /// </summary>
        /// <param name="XSDMsgDefNamespace">A message definition namespace to compare with.</param>
        public Boolean Equals(XSD_MsgDefNamespace XSDMsgDefNamespace)

            => String.Equals(InternalId,
                             XSDMsgDefNamespace.InternalId,
                             StringComparison.OrdinalIgnoreCase);

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => InternalId?.ToLower().GetHashCode() ?? 0;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => InternalId ?? "";

        #endregion

    }

}
