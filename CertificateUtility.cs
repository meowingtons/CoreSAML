//-----------------------------------------------------------------------
// <copyright file="CertificateUtility.cs" company="CoverMyMeds">
//  Copyright (c) 2012 CoverMyMeds.  All rights reserved.
//  This code is presented as reference material only.
// </copyright>
//-----------------------------------------------------------------------

using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace CoreSAML
{
    /// <summary>
    /// Methods specific to interacting with certificate on the machine
    /// </summary>
    public class CertificateUtility
    {

        /// <summary>
        /// Use an X509 certificate to append a computed signature to an XML serialized Response
        /// </summary>
        /// <param name="xmlSerializedSamlResponse"></param>
        /// <param name="referenceUri">Assertion ID from SAML Response</param>
        /// <param name="signingCert">X509 Certificate for signing</param>
        /// <remarks>Referenced this article:
        ///     http://www.west-wind.com/weblog/posts/2008/Feb/23/Digitally-Signing-an-XML-Document-and-Verifying-the-Signature
        /// </remarks>
        public static void AppendSignatureToXmlDocument(ref XmlDocument xmlSerializedSamlResponse, string referenceUri, X509Certificate2 signingCert)
        {
            XmlNamespaceManager ns = new XmlNamespaceManager(xmlSerializedSamlResponse.NameTable);
            ns.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            XmlElement xeAssertion = xmlSerializedSamlResponse.DocumentElement.SelectSingleNode("saml:Assertion", ns) as XmlElement;

            //SignedXml signedXML = new SignedXml(XMLSerializedSAMLResponse);
            SignedXml signedXml = new SignedXml(xeAssertion)
            {
                SigningKey = signingCert.PrivateKey
            };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            Reference reference = new Reference
            {
                Uri = referenceUri
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();

            XmlElement signature = signedXml.GetXml();

            if (xeAssertion == null) return;
            XmlElement xeIssuer = xeAssertion.SelectSingleNode("saml:Issuer", ns) as XmlElement;
            xeAssertion.InsertAfter(signature, xeIssuer);
        }
    }
}
