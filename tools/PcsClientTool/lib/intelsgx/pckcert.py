from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.backends import default_backend
import pyasn1
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import univ


id_cdp_extensionStr = '2.5.29.31'
id_ce_sGXExtensionsStr = '1.2.840.113741.1.13.1'

id_ce_sGXExtensions = univ.ObjectIdentifier(id_ce_sGXExtensionsStr)

id_ce_sGXExtensions_pPID = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".1")
id_ce_sGXExtensions_tCB = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2")
id_ce_sGXExtensions_pCE_ID = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".3")
id_ce_sGXExtensions_fMSPC = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".4")
id_ce_sGXExtensions_sGXType = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".5")
id_ce_sGXExtensions_platformInstanceID = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".6")
id_ce_sGXExtensions_configuration = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".7")

id_ce_tCB_sGXTCBComp01SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.1")
id_ce_tCB_sGXTCBComp02SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.2")
id_ce_tCB_sGXTCBComp03SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.3")
id_ce_tCB_sGXTCBComp04SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.4")
id_ce_tCB_sGXTCBComp05SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.5")
id_ce_tCB_sGXTCBComp06SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.6")
id_ce_tCB_sGXTCBComp07SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.7")
id_ce_tCB_sGXTCBComp08SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.8")
id_ce_tCB_sGXTCBComp09SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.9")
id_ce_tCB_sGXTCBComp10SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.10")
id_ce_tCB_sGXTCBComp11SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.11")
id_ce_tCB_sGXTCBComp12SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.12")
id_ce_tCB_sGXTCBComp13SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.13")
id_ce_tCB_sGXTCBComp14SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.14")
id_ce_tCB_sGXTCBComp15SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.15")
id_ce_tCB_sGXTCBComp16SVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.16")
id_ce_tCB_pCESVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.17")
id_ce_tCB_cPUSVN = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".2.18")

id_ce_configuration_dynamicPlatform = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".7.1")
id_ce_configuration_cachedKeys = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".7.2")
id_ce_configuration_sMTEnabled = univ.ObjectIdentifier(id_ce_sGXExtensionsStr + ".7.3")


class SgxExtensionPPID(univ.OctetString):
	pass


class SgxCPUSVN(univ.OctetString):
	pass


tcbAttributeMap = {
	id_ce_tCB_sGXTCBComp01SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp02SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp03SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp04SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp05SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp06SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp07SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp08SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp09SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp10SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp11SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp12SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp13SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp14SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp15SVN: univ.Integer(),
	id_ce_tCB_sGXTCBComp16SVN: univ.Integer(),
	id_ce_tCB_pCESVN: univ.Integer(),
	id_ce_tCB_cPUSVN: SgxCPUSVN(),
}


class SgxExtensionTCBEntry(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('tCBId', univ.ObjectIdentifier()),
		namedtype.NamedType('tCBValue', univ.Any(),
				    openType=opentype.OpenType('tCBId',
							       tcbAttributeMap))
	)


class SgxExtensionTCB(univ.SequenceOf):
	componentType = SgxExtensionTCBEntry()


class SgxExtensionPCEID(univ.OctetString):
	pass


class SgxExtensionFMSPC(univ.OctetString):
	pass


class SgxExtensionSGXType(univ.Enumerated):
	namedValues = namedval.NamedValues(
		('standard', 0),
		('scalable', 1),
		('scalableWithIntegrity', 2)
	)


class SgxExtensionPlatformInstanceID(univ.OctetString):
	pass


configurationAttributeMap = {
	id_ce_configuration_dynamicPlatform: univ.Boolean(),
	id_ce_configuration_cachedKeys: univ.Boolean(),
	id_ce_configuration_sMTEnabled: univ.Boolean(),
}


class SgxExtensionConfigurationEntry(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('configurationId', univ.ObjectIdentifier()),
		namedtype.NamedType('configurationValue', univ.Any(),
				    openType=opentype.OpenType('configurationId',
							       configurationAttributeMap))
	)


class SgxExtensionConfiguration(univ.SequenceOf):
	componentType = SgxExtensionConfigurationEntry()


extensionAttributeMap = {
	id_ce_sGXExtensions_pPID: SgxExtensionPPID(),
	id_ce_sGXExtensions_tCB: SgxExtensionTCB(),
	id_ce_sGXExtensions_pCE_ID: SgxExtensionPCEID(),
	id_ce_sGXExtensions_fMSPC: SgxExtensionFMSPC(),
	id_ce_sGXExtensions_sGXType: SgxExtensionSGXType(),
	id_ce_sGXExtensions_platformInstanceID: SgxExtensionPlatformInstanceID(),
	id_ce_sGXExtensions_configuration: SgxExtensionConfiguration(),
}


class SgxExtensionEntry(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType('sGXExtensionId', univ.ObjectIdentifier()),
		namedtype.NamedType('sGXExtensionValue', univ.Any(),
				    openType=opentype.OpenType('sGXExtensionId',
							       extensionAttributeMap))
	)


class SgxExtension(univ.SequenceOf):
	componentType = SgxExtensionEntry()


class SgxPckCertificateExtensions:

	def __init__(self):
		self.ca= ''
		self._data= None

	def _parse_asn1(self, extensionData):
		parsed, extra= der_decoder(extensionData,
					   asn1Spec=SgxExtension(),
					   decodeOpenTypes=True)
		return parsed

	def parse_pem_certificate(self, pem):
		cert= x509.load_pem_x509_certificate(pem, default_backend())
		issuerCN = cert.issuer.rfc4514_string()
		if (issuerCN.find('Processor') != -1) :
			self.ca = 'PROCESSOR'
		elif (issuerCN.find('Platform') != -1) :
			self.ca = 'PLATFORM'
		else :
			self.ca = None
		
		sgxext= cert.extensions.get_extension_for_oid(
			ObjectIdentifier(id_ce_sGXExtensionsStr)
		)

		self._data= self._parse_asn1(sgxext.value.value)

	def get_root_ca_crl(self, pem):
		cert= x509.load_pem_x509_certificate(pem, default_backend())
		cdpext= cert.extensions.get_extension_for_oid(
			ObjectIdentifier(id_cdp_extensionStr)
		)

		return getattr(getattr(cdpext.value[0], "_full_name")[0], "value")

	def data(self, field):
		if self._data is None:
			return None

		ent = list(filter(lambda e: e['sGXExtensionId'] == field, self._data))[0]
		return ent['sGXExtensionValue']

	def _hex_data(self, field):
		val= self.data(field)
		if val is None:
			return None
		return bytes(val).hex()

	# Commonly-needed data fields
	#------------------------------

	def get_fmspc(self):
		return self._hex_data(id_ce_sGXExtensions_fMSPC)

	def get_ca(self):
		return self.ca

	def get_tcbm(self):
		tcb= self.data(id_ce_sGXExtensions_tCB)
		if tcb is None:
			return None
		ent= list(filter(lambda e: e['tCBId'] == id_ce_tCB_cPUSVN, tcb))[0]
		return bytes(ent["tCBValue"]).hex() + self.get_pcesvn()

	def get_pceid(self):
		return self._hex_data(id_ce_sGXExtensions_pCE_ID)

	def get_ppid(self):
		return self._hex_data(id_ce_sGXExtensions_pPID)

	def get_pcesvn(self):
		tcb= self.data(id_ce_sGXExtensions_tCB)
		ent= list(filter(lambda e: e['tCBId'] == id_ce_tCB_pCESVN, tcb))[0]
		return int(ent["tCBValue"]).to_bytes(2, byteorder='little').hex()
