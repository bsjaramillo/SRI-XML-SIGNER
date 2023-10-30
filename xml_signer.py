import base64
from datetime import datetime
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
import xml.etree.ElementTree as ET


# Namespaces
xmldsig_uri = "http://www.w3.org/2000/09/xmldsig#"
xmletsi_uri = "http://uri.etsi.org/01903/v1.3.2#"

# Register namespaces acording to the xml document example provided by the SRI
ET.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
ET.register_namespace("etsi", "http://uri.etsi.org/01903/v1.3.2#")


def load_xml_document(xml_path):
    return ET.parse(xml_path)


def load_p12(p12_path, password):
    with open(p12_path, 'rb') as f:
        p12 = load_key_and_certificates(f.read(), password.encode())
        return p12[0], p12[1]


def generate_unique_id(length=6):
    return str(secrets.randbelow(10**6)).zfill(length)


def create_element(parent_element, tag, namespace_uri=xmldsig_uri, **kwargs):
    element = ET.Element(f'{{{namespace_uri}}}{tag}', **kwargs)
    parent_element.append(element)
    return element


def encode_xml_to_base64(element):
    return base64.b64encode(ET.tostring(element,
                                        method='xml', encoding='utf-8')).decode("utf-8")


if __name__ == "__main__":
    xml_document = load_xml_document('sri_example.xml')
    root_element = xml_document.getroot()
    key, certificate = load_p12('p12_file.p12', 'password')

    # Create the Signature element and added to root element
    signature = create_element(root_element,
                               'Signature', **{"Id": f"Signature{generate_unique_id()}", "xmlns:ds": xmldsig_uri, "xmlns:etsi": xmletsi_uri})

    # Create the SignedInfo element and added to Signature element
    signed_info = create_element(
        signature, 'SignedInfo', **{"Id": f"Signature-SignedInfo{generate_unique_id()}"})

    # Create the CanonicalizationMethod element and added to SignedInfo element
    create_element(signed_info, 'CanonicalizationMethod', **{
                   "Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"})

    # Create the SignatureMethod element and added to SignedInfo element
    create_element(signed_info, 'SignatureMethod', **{
                   "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"})
    # Create the Reference element and added to SignedInfo element
    reference = create_element(signed_info, 'Reference', **{
                               "Id": f"SignedPropertiesID{generate_unique_id()}",
                               "Type": "http://uri.etsi.org/01903#SignedProperties",
                               "URI": f"#{signature.attrib['Id']}-SignedProperties{generate_unique_id()}",
                               })

    # Create the DigestMethod element and added to Reference element
    create_element(reference, 'DigestMethod', **{
                   "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"})
    # Create the DigestValue element and added to Reference element
    # Calculate the digest value of the SignedInfo element and set it to the DigestValue element
    signed_info_bytes = ET.tostring(
        signed_info, method='xml', encoding='utf-8')
    digest = hashes.Hash(hashes.SHA256())
    digest.update(signed_info_bytes)
    digest_value = base64.b64encode(digest.finalize()).decode("utf-8")
    create_element(reference, 'DigestValue').text = digest_value

    # Create the Reference certificate element and added to SignedInfo element
    reference_certificate = create_element(signed_info, 'Reference', **{
                                           "URI": f"#Certificate{generate_unique_id(7)}",
                                           })

    # Create the DigestMethod element and added to Reference certificate element
    create_element(reference_certificate, 'DigestMethod', **{
                   "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"})
    # Create the DigestValue element and added to Reference certificate element
    # Calculate the digest value of the certificate and set it to the DigestValue element
    certificate_info_bytes = certificate.public_bytes(
        serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate_info_bytes)
    digest_value = base64.b64encode(digest.finalize()).decode("utf-8")
    create_element(reference_certificate, 'DigestValue').text = digest_value

    # Create the Reference voucher element and added to SignedInfo element
    reference_voucher = create_element(signed_info, 'Reference', **{
        "Id": f"Reference-ID-{generate_unique_id()}",
        "URI": f"#comprobante",
    })

    # Create the Transforms element and added to Reference voucher element
    transforms = create_element(reference_voucher, 'Transforms')
    # Create the Transform element and added to Transforms element
    create_element(transforms, 'Transform', **{
                   "Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"})

    # Create the DigestMethod element and added to Reference voucher element
    create_element(reference_voucher, 'DigestMethod', **{
                   "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"})
    # Create the DigestValue element and added to Reference voucher element
    # Calculate the digest value of the voucher and set it to the DigestValue element
    certificate_info_bytes = certificate.public_bytes(
        serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate_info_bytes)
    digest_value = base64.b64encode(digest.finalize()).decode("utf-8")
    create_element(reference_voucher, 'DigestValue').text = digest_value

    # Create the SignatureValue element and added to Signature element
    # Calculate the signature value of the SignedInfo element and set it to the SignatureValue element
    signature_value = create_element(
        signature, 'SignatureValue', **{"Id": f"SignatureValue{generate_unique_id()}"})

    signature_value_bytes = key.sign(
        signed_info_bytes, padding.PKCS1v15(), hashes.SHA256())
    signature_value.text = base64.b64encode(
        signature_value_bytes).decode("utf-8")

    # Create the KeyInfo element and added to Signature element
    key_info = create_element(signature, 'KeyInfo', **{
                              "Id": reference_certificate.attrib['URI'].removeprefix("#")})

    # Create the X509Data element and added to KeyInfo element
    x509_data = create_element(key_info, 'X509Data')

    # Create the X509Certificate element and added to X509Data element
    # Set the certificate value to the X509Certificate element
    x509_certificate = create_element(x509_data, 'X509Certificate')
    x509_certificate.text = base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)).decode("utf-8")

    # Create KeyValue element and added to KeyInfo element
    key_value = create_element(key_info, 'KeyValue')
    # Create RSAKeyValue element and added to KeyValue element
    rsa_key_value = create_element(key_value, 'RSAKeyValue')

    # Create Modulus element and added to RSAKeyValue element
    # Set the modulus value of the certificate to the Modulus element
    modulus = create_element(rsa_key_value, 'Modulus')
    modulus.text = base64.b64encode(
        key.public_key().public_numbers().n.to_bytes(256, 'big')).decode("utf-8")

    # Create Exponent element and added to RSAKeyValue element
    # Set the exponent value of the certificate to the Exponent element
    exponent = create_element(rsa_key_value, 'Exponent')
    exponent.text = base64.b64encode(
        key.public_key().public_numbers().e.to_bytes(4, "little")).decode("utf-8")

    # Create Object element and added to Signature element
    object_element = create_element(signature, 'Object', **{
                                    "Id": f"{signature.attrib['Id']}-Object{generate_unique_id()}"})

    # Create QualifyingProperties element and added to Object element
    qualifying_properties = create_element(
        object_element, 'QualifyingProperties', xmletsi_uri,  **{"Target": f"#{signature.attrib['Id']}"})

    # Create SignedProperties element and added to QualifyingProperties element
    signed_properties = create_element(
        qualifying_properties, 'SignedProperties', xmletsi_uri, **{"Id": f"{signature.attrib['Id']}-{reference.attrib['Id']}"})

    # Create SignedSignatureProperties element and added to SignedProperties element
    signed_signature_properties = create_element(
        signed_properties, 'SignedSignatureProperties', xmletsi_uri)

    # Create SigningTime element and added to SignedSignatureProperties element
    create_element(signed_signature_properties,
                   'SigningTime', xmletsi_uri).text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # Create SigningCertificate element and added to SignedSignatureProperties element
    signing_certificate = create_element(
        signed_signature_properties, 'SigningCertificate', xmletsi_uri)

    # Create Cert element and added to SigningCertificate element
    cert = create_element(signing_certificate, 'Cert', xmletsi_uri)

    # Create CertDigest element and added to Cert element
    cert_digest = create_element(cert, 'CertDigest', xmletsi_uri)

    # Create DigestMethod element and added to CertDigest element
    create_element(cert_digest, 'DigestMethod', **{
                   "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"})

    # Create DigestValue element and added to CertDigest element
    # Calculate the digest value of the certificate and set it to the DigestValue element
    digest = hashes.Hash(hashes.SHA256())
    digest.update(certificate_info_bytes)
    digest_value = base64.b64encode(digest.finalize()).decode("utf-8")
    create_element(cert_digest, 'DigestValue').text = digest_value

    # Create IssuerSerial element and added to Cert element
    issuer_serial = create_element(cert, 'IssuerSerial', xmletsi_uri)

    # Create X509IssuerName element and added to IssuerSerial element
    # Set the issuer name of the certificate to the X509IssuerName element
    create_element(
        issuer_serial, 'X509IssuerName').text = certificate.issuer.rfc4514_string()

    # Create X509SerialNumber element and added to IssuerSerial element
    # Set the serial number of the certificate to the X509SerialNumber element
    create_element(
        issuer_serial, 'X509SerialNumber').text = str(certificate.serial_number)

    # Create SignedDataObjectProperties element and added to SignedSignatureProperties element
    signed_data_object_properties = create_element(
        signed_properties, 'SignedDataObjectProperties', xmletsi_uri)

    # Create DataObjectFormat element and added to SignedDataObjectProperties element
    data_object_format = create_element(
        signed_data_object_properties, 'DataObjectFormat', xmletsi_uri, **{"ObjectReference": f"#{reference_voucher.attrib['Id']}"})

    # Create Description element and added to DataObjectFormat element
    create_element(data_object_format,
                   'Description', xmletsi_uri).text = "contenido comprobante"

    # Create MimeType element and added to DataObjectFormat element
    create_element(data_object_format, 'MimeType',
                   xmletsi_uri).text = "text/xml"

    ET.indent(xml_document)
    xml_signed_filename = "generated_signed_document.xml"
    xml_document.write(xml_signed_filename, method='xml',
                       encoding="utf-8", xml_declaration=True)
