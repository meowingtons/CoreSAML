//-----------------------------------------------------------------------
// <copyright file="SAML20Assertion.cs" company="CoverMyMeds">
//  Copyright (c) 2012 CoverMyMeds.  All rights reserved.
//  This code is presented as reference material only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CoreSAML
{
    /// <summary>
    /// Encapsulate functionality for building a SAML Response using the Schema object
    ///     created by xsd.exe from the OASIS spec
    /// </summary>
    /// <remarks>Lots of guidance from this CodeProject implementation
    ///     http://www.codeproject.com/Articles/56640/Performing-a-SAML-Post-with-C#xx0xx
    /// </remarks>
    // ReSharper disable once UnusedMember.Global
    public class Saml20Assertion
    {
        /// <summary>
        /// Build a signed XML SAML Response string to be inlcuded in an HTML Form
        /// for POSTing to a SAML Service Provider
        /// </summary>
        /// <param name="issuer">Identity Provider - Used to match the certificate for verifying 
        ///     Response signing</param>
        /// <param name="assertionExpirationMinutes">Assertion lifetime</param>
        /// <param name="audience"></param>
        /// <param name="subject"></param>
        /// <param name="recipient"></param>
        /// <param name="attributes">Dictionary of attributes to send through for user SSO</param>
        /// <param name="signingCert">X509 Certificate used to sign Assertion</param>
        /// <returns></returns>
        // ReSharper disable once UnusedMember.Global
        public static string CreateSaml20Response(string issuer,
            int assertionExpirationMinutes,
            string audience,
            string subject,
            string recipient,
            Dictionary<string, string> attributes,
            X509Certificate2 signingCert)
        {
            // Create SAML Response object with a unique ID and correct version
            ResponseType response = new ResponseType
            {
                ID = "_" + Guid.NewGuid(),
                Version = "2.0",
                IssueInstant = DateTime.UtcNow,
                Destination = recipient.Trim(),
                Issuer = new NameIDType {Value = issuer.Trim()},
                Status = new StatusType
                {
                    StatusCode = new StatusCodeType {Value = "urn:oasis:names:tc:SAML:2.0:status:Success"}
                },
                Items = new object[]
                {
                    CreateSaml20Assertion(issuer, assertionExpirationMinutes, audience, subject, recipient, attributes)
                }
            };

            // Put SAML 2.0 Assertion in Response

            XmlDocument xmlResponse = SerializeAndSignSamlResponse(response, signingCert);

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(xmlResponse.OuterXml));
        }

        /// <summary>
        /// Accepts SAML Response, serializes it to XML and signs using the supplied certificate
        /// </summary>
        /// <param name="response">SAML 2.0 Response</param>
        /// <param name="signingCert">X509 certificate</param>
        /// <returns>XML Document with computed signature</returns>
        private static XmlDocument SerializeAndSignSamlResponse(ResponseType response, X509Certificate2 signingCert)
        {
            // Set serializer and writers for action
            XmlSerializer responseSerializer = new XmlSerializer(response.GetType());
            StringWriter stringWriter = new StringWriter();
            XmlWriter responseWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = true, Encoding = Encoding.UTF8 });
            responseSerializer.Serialize(responseWriter, response);
            responseWriter.Close();
            XmlDocument xmlResponse = new XmlDocument();
            xmlResponse.LoadXml(stringWriter.ToString());

            // Set the namespace for prettier and more consistent XML
            XmlNamespaceManager ns = new XmlNamespaceManager(xmlResponse.NameTable);
            ns.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

            CertificateUtility.AppendSignatureToXmlDocument(ref xmlResponse, "#" + ((AssertionType)response.Items[0]).ID, signingCert);

            return xmlResponse;
        }

        /// <summary>
        /// Creates a SAML 2.0 Assertion Segment for a Response
        /// Simple implmenetation assuming a list of string key and value pairs
        /// </summary>
        /// <param name="issuer"></param>
        /// <param name="assertionExpirationMinutes"></param>
        /// <param name="audience"></param>
        /// <param name="subject"></param>
        /// <param name="recipient"></param>
        /// <param name="attributes">Dictionary of string key, string value pairs</param>
        /// <returns>Assertion to sign and include in Response</returns>
        private static AssertionType CreateSaml20Assertion(string issuer,
            int assertionExpirationMinutes,
            string audience,
            string subject,
            string recipient,
            Dictionary<string, string> attributes)
        {
            AssertionType newAssertion = new AssertionType
            {
                Version = "2.0",
                IssueInstant = DateTime.UtcNow,
                ID = "_" + Guid.NewGuid(),
                Issuer = new NameIDType {Value = issuer.Trim()}
            };

            // Create Issuer

            // Create Assertion Subject
            SubjectType subjectType = new SubjectType();
            NameIDType subjectNameIdentifier = new NameIDType { Value = subject.Trim(), Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" };
            SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType { Method = "urn:oasis:names:tc:SAML:2.0:cm:bearer", SubjectConfirmationData = new SubjectConfirmationDataType { NotOnOrAfter = DateTime.UtcNow.AddMinutes(assertionExpirationMinutes), Recipient = recipient } };
            subjectType.Items = new object[] { subjectNameIdentifier, subjectConfirmation };
            newAssertion.Subject = subjectType;

            // Create Assertion Conditions
            ConditionsType conditions = new ConditionsType
            {
                NotBefore = DateTime.UtcNow,
                NotBeforeSpecified = true,
                NotOnOrAfter = DateTime.UtcNow.AddMinutes(assertionExpirationMinutes),
                NotOnOrAfterSpecified = true,
                Items = new ConditionAbstractType[] { new AudienceRestrictionType { Audience = new[] { audience.Trim() } } }
            };
            newAssertion.Conditions = conditions;

            // Add AuthnStatement and Attributes as Items
            AuthnStatementType authStatement = new AuthnStatementType { AuthnInstant = DateTime.UtcNow, SessionIndex = newAssertion.ID };
            AuthnContextType context = new AuthnContextType
            {
                ItemsElementName = new[] { ItemsChoiceType5.AuthnContextClassRef },
                Items = new object[] { "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" }
            };
            authStatement.AuthnContext = context;

            AttributeStatementType attributeStatement = new AttributeStatementType
            {
                Items = new object[attributes.Count]
            };
            int i = 0;
            foreach (KeyValuePair<string, string> attribute in attributes)
            {
                attributeStatement.Items[i] = new AttributeType
                {
                    Name = attribute.Key,
                    AttributeValue = new object[] { attribute.Value },
                    NameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                };
                i++;
            }

            newAssertion.Items = new StatementAbstractType[] { authStatement, attributeStatement };

            return newAssertion;
        }

    }
}
