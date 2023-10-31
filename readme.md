# SRI XML SIGNER WITH XADES BES

This is a implementation in python to sign a XML document with the XAdES-BES formart. Following the SRI specifications, provided in its [data sheet](https://www.sri.gob.ec/o/sri-portlet-biblioteca-alfresco-internet/descargar/ba6330ae-9194-4090-9aff-4326655bbfa1/FICHA%20TE%cc%81CNICA%20COMPROBANTES%20ELECTRO%cc%81NICOS%20ESQUEMA%20OFFLINE%20Versio%cc%81n%202.24.pdf).

This takes an XML document like this:

```xml
<?xml version='1.0' encoding='utf-8'?>
<factura Id="comprobante" version="1.0.0">
    <infoTributaria>
        <ambiente>1</ambiente>
        <tipoEmision>1</tipoEmision>
        <razonSocial>SERVICIO DE RENTAS INTERNAS</razonSocial>
        <nombreComercial>LE HACE BIEN AL PAIS</nombreComercial>
        <ruc>1760013210001</ruc>
        <claveAcceso>0503201201176001321000110010030009900641234567814</claveAcceso>
        <codDoc>01</codDoc>
        <estab>001</estab>
        <ptoEmi>003</ptoEmi>
        <secuencial>000990064</secuencial>
        <dirMatriz>AMAZONAS Y ROCA</dirMatriz>
    </infoTributaria>
    <infoFactura>
        <fechaEmision>05/03/2012</fechaEmision>
        <dirEstablecimiento>SALINAS Y SANTIAGO</dirEstablecimiento>
        <contribuyenteEspecial>12345</contribuyenteEspecial>
        <obligadoContabilidad>SI</obligadoContabilidad>
        <tipoIdentificacionComprador>05</tipoIdentificacionComprador>
        <razonSocialComprador>EGUIGUREN PENARRETA GABRIEL FERNANDO</razonSocialComprador>
        <identificacionComprador>1103029144</identificacionComprador>
        <totalSinImpuestos>100.00</totalSinImpuestos>
        <totalDescuento>0.00</totalDescuento>
        <totalConImpuestos>
            <totalImpuesto>
                <codigo>2</codigo>
                <codigoPorcentaje>2</codigoPorcentaje>
                <baseImponible>100.00</baseImponible>
                <valor>12.00</valor>
            </totalImpuesto> 109 </totalConImpuestos>
        <propina>0.00</propina>
        <importeTotal>112.00</importeTotal>
        <moneda>DÓLAR</moneda>
    </infoFactura>
    <detalles>
        <detalle>
            <codigoPrincipal>001</codigoPrincipal>
            <codigoAuxiliar>001</codigoAuxiliar>
            <descripción>SILLA DE MADERA</descripción>
            <cantidad>1.00</cantidad>
            <precioUnitario>100.00</precioUnitario>
            <descuento>0.00</descuento>
            <precioTotalSinImpuesto>100.00</precioTotalSinImpuesto>
            <impuestos>
                <impuesto>
                    <codigo>2</codigo>
                    <codigoPorcentaje>2</codigoPorcentaje>
                    <tarifa>12.00</tarifa>
                    <baseImponible>100.00</baseImponible>
                    <valor>12.00</valor>
                </impuesto>
            </impuestos>
        </detalle>
    </detalles>
    <infoAdicional>
        <campoAdicional nombre="Dirección">LOS PERALES Y AV. ELOY ALFARO</campoAdicional>
        <campoAdicional nombre="Teléfono">2123123</campoAdicional>
        <campoAdicional nombre="Email">gfeguiguren@sri.gob.ec</campoAdicional>
    </infoAdicional>
</factura>
```

Expected signature output according the SRI specifications:

```xml
<?xml version='1.0' encoding='utf-8'?>

<factura Id="comprobante" version="1.0.0">
  <!--rest of xml -->
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#" Id="Signature620397">
        <ds:SignedInfo Id="Signature-SignedInfo814463">
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>
            <ds:Reference Id="SignedPropertiesID157683"
                Type="http://uri.etsi.org/01903#SignedProperties"
                URI="#Signature620397-SignedProperties24123">
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
            <ds:Reference URI="#Certificate1562780">
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
            <ds:Reference Id="Reference-ID-363558" URI="#comprobante">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue Id="SignatureValue398963"></ds:SignatureValue>
        <ds:KeyInfo Id="Certificate1562780">
            <ds:X509Data>
                <ds:X509Certificate></ds:X509Certificate>
            </ds:X509Data>
            <ds:KeyValue>
                <ds:RSAKeyValue>
                    <ds:Modulus></ds:Modulus>
                    <ds:Exponent>AQAB</ds:Exponent>
                </ds:RSAKeyValue>
            </ds:KeyValue>
        </ds:KeyInfo>
        <ds:Object Id="Signature620397-Object231987">
            <etsi:QualifyingProperties Target="#Signature620397">
                <etsi:SignedProperties Id="Signature620397-SignedProperties24123">
                    <etsi:SignedSignatureProperties>
                        <etsi:SigningTime>2012-03-05T16:57:32-05:00</etsi:SigningTime>
                        <etsi:SigningCertificate>
                            <etsi:Cert>
                                <etsi:CertDigest>
                                    <ds:DigestMethod
                                        Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                                    <ds:DigestValue>xUQewsj7MrjSfyMnhWz5DhQnWJM=</ds:DigestValue>
                                </etsi:CertDigest>
                                <etsi:IssuerSerial>
                                    <ds:X509IssuerName>CN=AC BANCO CENTRAL DEL
                                        ECUADOR,L=QUITO,OU=ENTIDAD DE CERTIFICACION DE
                                        INFORMACION-ECIBCE,O=BANCO CENTRAL DEL ECUADOR,C=EC</ds:X509IssuerName>
                                    <ds:X509SerialNumber>1312833444</ds:X509SerialNumber>
                                </etsi:IssuerSerial>
                            </etsi:Cert>
                        </etsi:SigningCertificate>
                    </etsi:SignedSignatureProperties>
                    <etsi:SignedDataObjectProperties>
                        <etsi:DataObjectFormat ObjectReference="#Reference-ID-363558">
                            <etsi:Description>contenido comprobante</etsi:Description>
                            <etsi:MimeType>text/xml</etsi:MimeType>
                        </etsi:DataObjectFormat>
                    </etsi:SignedDataObjectProperties>
                </etsi:SignedProperties>
            </etsi:QualifyingProperties>
        </ds:Object>
    </ds:Signature>
</factura>
```

Final output:

```xml
<?xml version='1.0' encoding='utf-8'?>

<factura xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#" Id="comprobante" version="1.0.0">
  <!--rest of xml -->
  <ds:Signature Id="Signature873144" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#">
    <ds:SignedInfo Id="Signature-SignedInfo342832">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
      <ds:Reference Id="SignedPropertiesID578828" Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature873144-SignedProperties840655">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <ds:DigestValue>PeyTvpfMD8/OcvGILKSYHeAqy4b93ulWeJYkIOUEw88=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference URI="#Certificate0620708">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <ds:DigestValue>BJm4gSgLsbEPkdQ+3JTtfpX/8680YoesfGLguZmqQn8=</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Id="Reference-ID-310606" URI="#comprobante">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <ds:DigestValue>BJm4gSgLsbEPkdQ+3JTtfpX/8680YoesfGLguZmqQn8=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue Id="SignatureValue762180">DV+w1v5hMY979UrOrQQ2XDeO43BctaWRdcV2iM/apcYpGSpvya3ktn/FDthRfhjHDpzx7KmLaxALdP/YNbOKkFSV7hc4JcO/CWIoeijnbTX6qNqDTx6xQQdmTgb0FDlC2qGvzG6+YS7YKzoY2Dt18rMJKsunFBp5cTtLtmjcDJpt8/mJtV/a9eRAToje12iSVwp4Sc1bkOcvLWo9VpaRh8jUjvZ1Q9CW/TKDvGu2PAOwH2NPK8nVK06aHLDYf7rzxN6oQVJPqIdkm6FTa/wq9rBiy19DoNrbp/lcIAwsB/k97H9XxCT80EfkamPysZfPQTgrL4lFENcDFnoI6agldQ==</ds:SignatureValue>
    <ds:KeyInfo Id="Certificate0620708">
      <ds:X509Data>
        <ds:X509Certificate>MIID3DCCAsSgAwIBAgIUOJ0QKhRP7S4eFx/STu7G9WzLakkwDQYJKoZIhvcNAQELBQAwgYAxCzAJBgNVBAYTAkVDMRIwEAYDVQQIEwlQSUNISU5DSEExDjAMBgNVBAcTBVFVSVRPMR0wGwYDVQQKExRTUkkgVEVTVEVSIFhBREVTIEJFUzEPMA0GA1UECxMGUFlUSE9OMR0wGwYDVQQDExRTUkkgVEVTVEVSIFhBREVTIEJFUzAeFw0yMzEwMzAyMzI1MjVaFw0zMzEwMzAyMzI1MjVaMIGAMQswCQYDVQQGEwJFQzESMBAGA1UECBMJUElDSElOQ0hBMQ4wDAYDVQQHEwVRVUlUTzEdMBsGA1UEChMUU1JJIFRFU1RFUiBYQURFUyBCRVMxDzANBgNVBAsTBlBZVEhPTjEdMBsGA1UEAxMUU1JJIFRFU1RFUiBYQURFUyBCRVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN0cUYLplP3g9sC5pcw78aWqiENla6td3rZb+KuaOSO9vU8w5pHGbzLFzHdRydqIJ1h1gQ/ZXqRMwpiq8kbQ8pQrIXVO4ymLWS43xisskxLA7VbvLegP1yKbS2pwz3O7tdtqsRgIj7XmOTPXjRVa+ueGJpioI/Lbm7U8nrwGLXAiNxJCjYxNKyShJDGda6AaOan8i9Qzp9vrmiSgYL/OeTfOijT2LDK++TwV7feOVKPmPfv+vh5HYof94tK7chj9fRWNpfceg/zujgEIN/1kcWaHo1GPXA0JU/s9gXjmI5ilQNde2hEUGrBbSkJn2uVWEQW0Tit5IjHBQGI8ygyLsrAgMBAAGjTDBKMAkGA1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgTwMAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAAkmAQa6cDSYRWEyzJq8yq53YDuIz4ib8EOx/xSCKhXj02iEY2I5qL/aPzTfc+ZJF+RHnYXUfL+CW5I1ROpA+lm7fOQWnVobIBMiOnLnYy939L2e5ahxmxdDcBkOL9dquMOCwEAq352tm7jET4OllA75TG1YRlwiGXyICdp7NtptlpMZC4Bn24AX5RM4QRrDZG6cCJQBK479CJokR+rpSz8IQAy5PJwXQuxXxEgJOBvNrrZ+7G2cq33zTRQfktZGLrAdR3HRymV1PUyMxFXUV1tKRDOfDTkuYnYG/FBEZ/TY4WzwuSRIyiGe3o+OoBbgihF8U9yCMi6L4oxRMDPmZnA=</ds:X509Certificate>
      </ds:X509Data>
      <ds:KeyValue>
        <ds:RSAKeyValue>
          <ds:Modulus>zdHFGC6ZT94PbAuaXMO/GlqohDZWurXd62W/irmjkjvb1PMOaRxm8yxcx3UcnaiCdYdYEP2V6kTMKYqvJG0PKUKyF1TuMpi1kuN8YrLJMSwO1W7y3oD9cim0tqcM9zu7XbarEYCI+15jkz140VWvrnhiaYqCPy25u1PJ68Bi1wIjcSQo2MTSskoSQxnWugGjmp/IvUM6fb65okoGC/znk3zoo09iwyvvk8Fe33jlSj5j37/r4eR2KH/eLSu3IY/X0VjaX3HoP87o4BCDf9ZHFmh6NRj1wNCVP7PYF45iOYpUDXXtoRFBqwW0pCZ9rlVhEFtE4reSIxwUBiPMoMi7Kw==</ds:Modulus>
          <ds:Exponent>AQABAA==</ds:Exponent>
        </ds:RSAKeyValue>
      </ds:KeyValue>
    </ds:KeyInfo>
    <ds:Object Id="Signature873144-Object119978">
      <etsi:QualifyingProperties Target="#Signature873144">
        <etsi:SignedProperties Id="Signature873144-SignedPropertiesID578828">
          <etsi:SignedSignatureProperties>
            <etsi:SigningTime>2023-10-30T18:27:45</etsi:SigningTime>
            <etsi:SigningCertificate>
              <etsi:Cert>
                <etsi:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                  <ds:DigestValue>BJm4gSgLsbEPkdQ+3JTtfpX/8680YoesfGLguZmqQn8=</ds:DigestValue>
                </etsi:CertDigest>
                <etsi:IssuerSerial>
                  <ds:X509IssuerName>CN=SRI TESTER XADES BES,OU=PYTHON,O=SRI TESTER XADES BES,L=QUITO,ST=PICHINCHA,C=EC</ds:X509IssuerName>
                  <ds:X509SerialNumber>323206108277738201986045592173754726287804164681</ds:X509SerialNumber>
                </etsi:IssuerSerial>
              </etsi:Cert>
            </etsi:SigningCertificate>
          </etsi:SignedSignatureProperties>
          <etsi:SignedDataObjectProperties>
            <etsi:DataObjectFormat ObjectReference="#Reference-ID-310606">
              <etsi:Description>contenido comprobante</etsi:Description>
              <etsi:MimeType>text/xml</etsi:MimeType>
            </etsi:DataObjectFormat>
          </etsi:SignedDataObjectProperties>
        </etsi:SignedProperties>
      </etsi:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</factura>
```

## Usage

```python

from xml_signer import sign_xml
import xml.etree.ElementTree as ET

if __name__=="__main__":

    xml_signed=sign_xml("sri_example.xml","digital_certificate.p12","password")
    ET.ElementTree(xml_signed).write("generated_signed_document.xml", method='xml',
                          encoding="utf-8", xml_declaration=True)
```

#### libs

- [cryptography](https://cryptography.io/en/latest/)
- [xml.etree.ElementTree](https://docs.python.org/3/library/xml.etree.elementtree.html)
