using FursTester;
using Microsoft.Extensions.Configuration;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;


namespace Agitavit.FormNet.Infrastructure.Integrations
{
    public class FursService
    {
        private IConfiguration configuration;

        private string envelope = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:fu=\"http://www.fu.gov.si/\"><soapenv:Header/><soapenv:Body></soapenv:Body></soapenv:Envelope>";

        private string _serverCertThumbprint;
        private string _signCertSubject;

        public FursService(IConfiguration config)
        {
            configuration = config;
        }


        public void ExecuteCall()
        {
            // current certificate data saved in database
            var tenantCertThumbprint = configuration["TenantCertThumbprint"];
            this._serverCertThumbprint = configuration["ServerCertThumbprint"];
            this._signCertSubject = configuration["SignCertSubject"];

            // get tenant certificate used to sign XML send to FURS
            var tenantCertificate = this.GetCertificateFromStore(CertificateSearchKey.Thumbprint, tenantCertThumbprint, StoreName.My, StoreLocation.LocalMachine);

            // create XML request document
            var xmlDoc = File.ReadAllText(configuration["XML4FURS"]);

            //Console.WriteLine($"\n\nINPUT:\n{xmlDoc}");

            var signedXmlDoc = this.CreateXmlDoc(xmlDoc, tenantCertificate);

            //Console.WriteLine($"\n\nSigned INPUT:\n{signedXmlDoc.OuterXml}");
            File.WriteAllText(configuration["XML4FURS_Signed"], signedXmlDoc.OuterXml);

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;


            var (request, method) = CreateWebRequest(tenantCertificate);
            var responseXml = this.ExecuteWebRequest(request, signedXmlDoc);

            //Console.WriteLine($"\n\nFURS Response:\n{responseXml.OuterXml}");
            File.WriteAllText(configuration["XMLFromFurs"], responseXml.OuterXml);
        }




        #region ========== Helpers ==========

        private X509Certificate2 GetCertificateFromStore(CertificateSearchKey searchMode, string searchKey, StoreName storename, StoreLocation storeLocation)
        {
            if (string.IsNullOrEmpty(searchKey))
                return null;

            X509Certificate2 certificate = null;
            using (var store = new X509Store(storename, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var c in store.Certificates)
                {
                    switch (searchMode)
                    {
                        case CertificateSearchKey.Thumbprint:
                            if (c.Thumbprint.Equals(searchKey, StringComparison.OrdinalIgnoreCase))
                            {
                                certificate = c;
                            }
                            break;
                        case CertificateSearchKey.Subject:
                            if (c.Subject.Equals(searchKey, StringComparison.OrdinalIgnoreCase))
                            {
                                certificate = c;
                            }
                            break;
                        default:
                            break;
                    }

                    if (certificate != null)
                    {
                        break;
                    }
                }
            }

            if (certificate == null)
            {
                Console.WriteLine($"Certificate for '{searchKey}' not found in certificate store. FURS call will not be executed!");
            }
            else
            {
                Console.WriteLine($"Certificate found with details - Subject: '{certificate.Subject}', SerialNumber: '{certificate.GetSerialNumberString()}', Valid from: '{certificate.GetEffectiveDateString()}', Valid to: '{certificate.GetExpirationDateString()}'");
            }

            return certificate;
        }

        private (HttpWebRequest request, string method) CreateWebRequest(X509Certificate2 tenantCertificate)
        {
            var fursUrl = configuration["FursUrl"];
            int timeout = 0;
            // (+) Value 0 will not work when executing FURS call
            if (timeout == 0)
            {
                timeout = 4; // Hardcoded value incase its missing in database
            }

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(fursUrl);

            // the Timeout property expects the paremeter in miliseconds, the FVServiceTimeoutSeconds property is stored in seconds
            webRequest.Timeout = timeout * 1000;
            var method = "";

            method = @"SOAPAction: /invoices/register";

            webRequest.Headers.Add(method);
            webRequest.ContentType = "text/xml; charset=UTF-8";
            webRequest.Accept = "text/xml";
            webRequest.Method = "POST";
            webRequest.KeepAlive = true;

            webRequest.ClientCertificates.Add(tenantCertificate);
            return (webRequest, method);
        }

        private XmlDocument ExecuteWebRequest(HttpWebRequest request, XmlDocument xmlDoc)
        {
            var soapResult = "";
            var responseXml = new XmlDocument();
            try
            {
                using (var stream = request.GetRequestStream())
                {
                    using var sw = new StreamWriter(stream, new UTF8Encoding(false, true));
                    xmlDoc.Save(sw);
                }

                using (WebResponse response = request.GetResponse())
                {
                    using (StreamReader rd = new StreamReader(response.GetResponseStream()))
                    {
                        soapResult = rd.ReadToEnd();
                    }
                    response.Close();
                }

                responseXml.PreserveWhitespace = true;
                responseXml.LoadXml(soapResult);
                return responseXml;
            }
            finally
            {
                if (Boolean.Parse(configuration["ValidateFursCertificate"]))
                    ServicePointManager.ServerCertificateValidationCallback -= new RemoteCertificateValidationCallback(ValidateCertificate);
            }
        }

        private XmlDocument SignXmlSha256(XmlDocument input, X509Certificate2 signCert, string referenceUri, string elementToAppendSignatureTo)
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

            // Check arguments. 
            if (input == null)
            {
                throw new ArgumentException("input");
            }
            if (signCert == null)
            {
                throw new ArgumentException("signingCert");
            }

            // Create a SignedXml object.
            var signedXml = new SignedXml(input);

            //var rsaCSP = (RSACryptoServiceProvider)signCert.GetRSAPrivateKey();
            //var tmp2 = (RSACryptoServiceProvider)tmp;

            CspParameters cspParameters = new CspParameters();
            //cspParameters.KeyContainerName = rsaCSP.CspKeyContainerInfo.KeyContainerName; //signCert.GetNameInfo(X509NameType.SimpleName, false);
            //cspParameters.KeyNumber = rsaCSP.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2; //1;
            cspParameters.KeyContainerName = signCert.GetNameInfo(X509NameType.SimpleName, false);
            cspParameters.KeyNumber = 1;
            cspParameters.Flags = CspProviderFlags.UseMachineKeyStore;

            RSACryptoServiceProvider rsaAesCSP = new RSACryptoServiceProvider(cspParameters);
            Console.WriteLine($"KeyContainerName: {cspParameters.KeyContainerName}");

            signedXml.SigningKey = rsaAesCSP;

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data();
            keyInfoData.AddIssuerSerial(signCert.Issuer, signCert.SerialNumber);
            Console.WriteLine($"Issuer: {signCert.Issuer}");
            Console.WriteLine($"Issuer: {signCert.SerialNumber}");
            Console.WriteLine($"SubjectName: {signCert.SubjectName.Name}");

            X509Extension extension = signCert.Extensions[1];
            var asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            keyInfoData.AddSubjectName(signCert.SubjectName.Name);

            // Create a reference to be signed.
            var reference = new Reference();
            reference.Uri = referenceUri;
            reference.DigestMethod = @"http://www.w3.org/2001/04/xmlenc#sha256";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            //Console.WriteLine($"BEFORE: {signedXml.ExObjectToJson()}");

            // Compute the signature.            
            signedXml.ComputeSignature();

            //Console.WriteLine($"AFTER: {signedXml.ExObjectToJson()}");

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            var xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            XmlNode element = null;
            XmlNodeList elementList = input.GetElementsByTagName(elementToAppendSignatureTo);
            if (elementList.Count == 0)
            {
                return null;
            }

            element = elementList[0];
            element.AppendChild(xmlDigitalSignature);
            SignedXml signedXml2 = new SignedXml(input);
            signedXml2.SigningKey = rsaAesCSP;
            signedXml2.AddReference(reference);
            signedXml2.KeyInfo = keyInfo;
            signedXml2.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            return input;
        }

        private XmlDocument SignXmlSha2562(XmlDocument input, string fileCertName, string fileCertPassword, string referenceUri, string elementToAppendSignatureTo)
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

            // Check arguments. 
            if (input == null)
            {
                throw new ArgumentException("input");
            }
           
            X509Certificate2 signCert = new X509Certificate2(fileCertName, fileCertPassword);
            // Create a SignedXml object.
            var signedXml = new SignedXml(input);

            //var rsaCSP = (RSACryptoServiceProvider)signCert.GetRSAPrivateKey();
            //var tmp2 = (RSACryptoServiceProvider)tmp;

            CspParameters cspParameters = new CspParameters();
            //cspParameters.KeyContainerName = rsaCSP.CspKeyContainerInfo.KeyContainerName; //signCert.GetNameInfo(X509NameType.SimpleName, false);
            //cspParameters.KeyNumber = rsaCSP.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2; //1;
            cspParameters.KeyContainerName = signCert.GetNameInfo(X509NameType.SimpleName, false);
            cspParameters.KeyNumber = 1;
            cspParameters.Flags = CspProviderFlags.UseMachineKeyStore;

            RSACryptoServiceProvider rsaAesCSP = new RSACryptoServiceProvider(cspParameters);
            Console.WriteLine($"KeyContainerName: {cspParameters.KeyContainerName}");

            signedXml.SigningKey = rsaAesCSP;

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data();
            keyInfoData.AddIssuerSerial(signCert.Issuer, signCert.SerialNumber);
            Console.WriteLine($"Issuer: {signCert.Issuer}");
            Console.WriteLine($"Issuer: {signCert.SerialNumber}");
            Console.WriteLine($"SubjectName: {signCert.SubjectName.Name}");

            X509Extension extension = signCert.Extensions[1];
            var asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            keyInfoData.AddSubjectName(signCert.SubjectName.Name);

            // Create a reference to be signed.
            var reference = new Reference();
            reference.Uri = referenceUri;
            reference.DigestMethod = @"http://www.w3.org/2001/04/xmlenc#sha256";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            //Console.WriteLine($"BEFORE: {signedXml.ExObjectToJson()}");

            // Compute the signature.            
            signedXml.ComputeSignature();

            //Console.WriteLine($"AFTER: {signedXml.ExObjectToJson()}");

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            var xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            XmlNode element = null;
            XmlNodeList elementList = input.GetElementsByTagName(elementToAppendSignatureTo);
            if (elementList.Count == 0)
            {
                return null;
            }

            element = elementList[0];
            element.AppendChild(xmlDigitalSignature);
            SignedXml signedXml2 = new SignedXml(input);
            signedXml2.SigningKey = rsaAesCSP;
            signedXml2.AddReference(reference);
            signedXml2.KeyInfo = keyInfo;
            signedXml2.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            return input;
        }

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine($"Certificate thumbprint from server: {((X509Certificate2)certificate).Thumbprint.ToLower()}", null);
            Console.WriteLine($"Certificate thumbprint from database: {_serverCertThumbprint.ToLower()}", null);

            bool result = this._serverCertThumbprint.ToLower() == ((X509Certificate2)certificate).Thumbprint.ToLower();

            if (result)
                Console.WriteLine("Server certificate verified", null);
            else
                Console.WriteLine("Server certificate not verified.", null);
            return result;
        }

        

        private XmlDocument CreateXmlDoc(string data, X509Certificate2 signCert)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(this.envelope);
            XmlNodeList nodes = xmlDoc.GetElementsByTagName("soapenv:Body");

            nodes[0].InnerXml = data;
            var el = "fu:BusinessPremiseRequest";
            if (Convert.ToBoolean(configuration["UseFromStorage"]))
            {
                xmlDoc = this.SignXmlSha256(xmlDoc, signCert, "#data", el);
            }
            else
            {
                xmlDoc = this.SignXmlSha2562(xmlDoc, configuration["TP_CertFilePath"], configuration["TP_CertPassword"], "#data", el);
            }
            

            return xmlDoc;
        }
    }





    #endregion

}
