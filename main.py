from xml_signer import sign_xml
import xml.etree.ElementTree as ET

if __name__=="__main__":

    xml_signed=sign_xml("sri_example.xml","digital_certificate.p12","password")
    ET.ElementTree(xml_signed).write("generated_signed_document.xml", method='xml',
                          encoding="utf-8", xml_declaration=True)