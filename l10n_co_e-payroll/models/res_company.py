from datetime import date, datetime, timedelta

from odoo import _, api, fields, models, tools
from odoo.exceptions import UserError, ValidationError
from pytz import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, pkcs12
from cryptography.x509 import oid
from cryptography.exceptions import InvalidSignature
from odoo import _, tools
from odoo.exceptions import UserError, ValidationError
import base64
from lxml import etree
from io import BytesIO

class ResCompanyInherit(models.Model):
    _inherit = "res.company"

    digital_certificate_payroll = fields.Text(
        string="Certificado Nomina digital público", required=True, default=""
    )
    software_identification_code_payroll = fields.Char(
        string="Código Nomina de identificación del software", required=True, default=""
    )
    identificador_set_pruebas_payroll = fields.Char(
        string="Identificador Nomina del SET de pruebas", required=True, default=""
    )
    software_pin_payroll = fields.Char(
        string="PIN Nomina del software", required=True, default=""
    )
    password_environment_payroll = fields.Char(
        string="Clave Nomina de ambiente", required=True, default=""
    )
    seed_code_payroll = fields.Integer(
        string="Código Nomina de semilla", required=True, default=5000000
    )
    issuer_name_payroll = fields.Char(
        string="Ente emisor Nomina del certificado", required=True, default=""
    )
    serial_number_payroll = fields.Char(
        string="Serial Nomina del certificado", required=True, default=""
    )
    document_repository_payroll = fields.Char(
        string="Ruta de almacenamiento de archivos Nomina", required=True, default=""
    )
    certificate_key_payroll = fields.Char(
        string="Clave del certificado P12 Nomina", required=True, default=""
    )
    pem = fields.Char(
        string="Nombre del archivo PEM del certificado", required=True, default=""
    )
    pem_file_payroll = fields.Binary("Archivo PEM")
    certificate = fields.Char(
        string="Nombre del archivo del certificado", required=True, default=""
    )
    certificate_file_payroll = fields.Binary("Archivo del certificado")
    production_payroll = fields.Boolean(
        string="Pase a producción Nomina", default=False
    )
    xml_response_numbering_range_payroll = fields.Text(
        string="Contenido XML de la respuesta DIAN a la consulta de rangos Nomina",
        readonly=True,
        default="",
    )


    def button_extract_certificate_payroll(self):
        password = self.certificate_key_payroll.encode('utf-8')
        archivo_key = base64.b64decode(self.certificate_file_payroll)
        try:
            private_key, x509, additional_certs = pkcs12.load_key_and_certificates(archivo_key, password)
        except Exception as ex:
            raise UserError(tools.ustr(ex))

        def get_reversed_rdns_name(rdns):
            """
            Gets the rdns String name, but in the right order.
            :param rdns: RDNS object
            :type rdns: cryptography.x509.Name
            :return: RDNS name
            """
            OID_NAMES = {
                oid.NameOID.COMMON_NAME: 'CN',
                oid.NameOID.COUNTRY_NAME: 'C',
                oid.NameOID.DOMAIN_COMPONENT: 'DC',
                oid.NameOID.EMAIL_ADDRESS: 'E',
                oid.NameOID.GIVEN_NAME: 'G',
                oid.NameOID.LOCALITY_NAME: 'L',
                oid.NameOID.ORGANIZATION_NAME: 'O',
                oid.NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
                oid.NameOID.SURNAME: 'SN'
            }
            name = ''
            for rdn in reversed(rdns):
                for attr in rdn:
                    if len(name) > 0:
                        name = name + ','
                    if attr.oid in OID_NAMES:
                        name = name + OID_NAMES[attr.oid]
                    else:
                        name = name + attr.oid._name
                    name = name + '=' + attr.value
            return name

        issuer = get_reversed_rdns_name(x509.issuer.rdns)

        s = base64.b64encode(x509.public_bytes(encoding=Encoding.DER))
        self.issuer_name_payroll = issuer
        self.serial_number_payroll = x509.serial_number
        self.digital_certificate_payroll = s.decode('utf-8')

        pem_data = x509.public_bytes(encoding=Encoding.PEM)
        self.pem = "Certificate.pem"
        self.pem_file_payroll = base64.b64encode(pem_data)