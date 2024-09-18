package internal.ike.handler

import config.Config
import engine.util.removeZero
import engine.util.toBigInteger
import engine.util.toUByteArrayString
import go.net.IP
import go.net.IPMask
import internal.gre.Gre
import internal.ike.context.*
import internal.ike.context.RandomNumberGenerator.generateRandomNumber
import internal.ike.message.*
import internal.ipsec.Ipsec
import internal.nas.dispatch.dispatchNas
import internal.nas.message.buildRegistrationRequest
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.nio.ByteBuffer
import java.nio.ByteOrder


private val log = LoggerFactory.getLogger("ike.handler")

const val PreSignalling: UInt = 0u
const val EAPSignalling: UInt = 1u
const val PostSignalling: UInt = 2u
const val TCPEstablishSignalling: UInt = 3u


fun handleIkeSaInit(ue: UeIke, ikeMsg: IKEMessage) {
    log.trace("handleIkeSaInit")

    // handle IKE SA INIT Response
    var securityAssociation: SecurityAssociation? = null
    val notifications = mutableListOf<Notification>()
    var sharedKeyData: ByteArray = byteArrayOf()
    var remoteNonce: ByteArray = byteArrayOf()
    var encryptionAlgorithmTransform: Transform? = null
    var pseudorandomFunctionTransform: Transform? = null
    var integrityAlgorithmTransform: Transform? = null
    var diffieHellmanGroupTransform: Transform? = null

    if (ikeMsg.flags.toInt() != Flag.ResponseBitCheck.value.toInt()) {
        println("ikeMsg.Flags not equals message.ResponseBitCheck")
        return
    }

    // recover UE information based on parameters of ike message
    for (ikePayload in ikeMsg.payloads) {
        when (ikePayload.type()) {
            IKEPayloadType.TypeSA -> securityAssociation = ikePayload as SecurityAssociation
            IKEPayloadType.TypeKE -> {
                val remotePublicKeyExchangeValue = (ikePayload as KeyExchange).keyExchangeData
                val remotePublicKeyExchangeValueBig = remotePublicKeyExchangeValue.removeZero().toBigInteger()
                sharedKeyData = remotePublicKeyExchangeValueBig.modPow(ue.getSecret(), ue.getFactor()).toByteArray()
                sharedKeyData = sharedKeyData.removeZero()
                log.trace("sharedKeyData [${sharedKeyData.size}] " + sharedKeyData.toUByteArrayString())
            }
            IKEPayloadType.TypeNiNr -> remoteNonce = (ikePayload as Nonce).nonceData
            IKEPayloadType.TypeN -> notifications.add(ikePayload as Notification)
            else -> {
                // TODO handle in ike payloads
            }
        }
    }

    // retrieve client context
    securityAssociation?.let {
        for (proposal in it.proposals) {
            // We need ENCR, PRF, INTEG, DH
            encryptionAlgorithmTransform = null
            pseudorandomFunctionTransform = null
            integrityAlgorithmTransform = null
            diffieHellmanGroupTransform = null

            if (proposal.encryptionAlgorithm.transforms.isNotEmpty()) {
                for (transform in proposal.encryptionAlgorithm.transforms) {
                    if (transform.transformID == ue.getEncryptionAlgorithm()) {
                        encryptionAlgorithmTransform = transform
                        break
                    }
                }
                if (encryptionAlgorithmTransform == null) {
                    continue
                }
            } else {
                continue // mandatory
            }

            if (proposal.pseudorandomFunction.transforms.isNotEmpty()) {
                for (transform in proposal.pseudorandomFunction.transforms) {
                    if (transform.transformID == ue.getPseudorandomFunction()) {
                        pseudorandomFunctionTransform = transform
                        break
                    }
                }
                if (pseudorandomFunctionTransform == null) {
                    continue
                }
            } else {
                continue // mandatory
            }

            if (proposal.integrityAlgorithm.transforms.isNotEmpty()) {
                for (transform in proposal.integrityAlgorithm.transforms) {
                    if (transform.transformID == ue.getIntegrityAlgorithm()) {
                        integrityAlgorithmTransform = transform
                        break
                    }
                }
                if (integrityAlgorithmTransform == null) {
                    continue
                }
            } else {
                continue // mandatory
            }

            if (proposal.diffieHellmanGroup.transforms.isNotEmpty()) {
                for (transform in proposal.diffieHellmanGroup.transforms) {
                    if (transform.transformID == ue.getDiffieHellmanGroup()) {
                        diffieHellmanGroupTransform = transform
                        break
                    }
                }
                if (diffieHellmanGroupTransform == null) {
                    continue
                }
            } else {
                continue // mandatory
            }
        }
    }

    val ikeSecurityAssociation = IkeSecurityAssociation()
    ikeSecurityAssociation.localSPI = ikeMsg.initiatorSPI
    ikeSecurityAssociation.remoteSPI = ikeMsg.responderSPI
    ikeSecurityAssociation.initiatorMessageID = ikeMsg.messageID
    ikeSecurityAssociation.responderMessageID = ikeMsg.messageID
    ikeSecurityAssociation.encryptionAlgorithm = encryptionAlgorithmTransform
    ikeSecurityAssociation.integrityAlgorithm = integrityAlgorithmTransform
    ikeSecurityAssociation.pseudorandomFunction = pseudorandomFunctionTransform
    ikeSecurityAssociation.diffieHellmanGroup = diffieHellmanGroupTransform
    ikeSecurityAssociation.concatenatedNonce = ue.getLocalNonce() + remoteNonce
    ikeSecurityAssociation.diffieHellmanSharedKey = sharedKeyData

    try {
        generateKeyForIKESA(ikeSecurityAssociation)
    } catch (e: Exception) {
        log.error(e.message)
        throw Exception("Generate key for IKE SA failed")
    }

    // create IKE security association
    ue.createN3IWFIKESecurityAssociation(ikeSecurityAssociation)

    // send IKE_AUTH
    val responseIKEMessage = IKEMessage()

    ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID++

    responseIKEMessage.buildIKEHeader(
        ue.n3iwfIkeSecurityAssociation!!.localSPI,
        ue.n3iwfIkeSecurityAssociation!!.remoteSPI,
        ExchangeType.IKE_AUTH.value.toUByte(),
        Flag.InitiatorBitCheck.value.toUByte(),
        ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID
    )

    val ikePayload = IKEPayloadContainer()

    // Identification
    ikePayload.buildIdentificationInitiator(IdentificationType.ID_FQDN.value.toByte(), "UE".toByteArray())

    // Security Association
    securityAssociation = ikePayload.buildSecurityAssociation()

    val attributeType: UShort = AttributeType.AttributeTypeKeyLength.value.toUShort()
    val keyLength: UShort = 256u

    // Proposal 1
    val inboundSPI = ue.generateSPI()
    val proposal = securityAssociation.proposals.buildProposal(1u, ProtocolType.TypeESP.value.toUByte(), inboundSPI)

    // ENCR
    proposal.encryptionAlgorithm.buildTransform(
        PayloadType.TypeEncryptionAlgorithm.value.toUByte(),
        ue.getEncryptionAlgorithm(),
        attributeType,
        keyLength,
        ByteArray(0)
    )

    // INTEG
    proposal.integrityAlgorithm.buildTransform(
        PayloadType.TypeIntegrityAlgorithm.value.toUByte(),
        ue.getIntegrityAlgorithm(),
        null,
        null,
        ByteArray(0)
    )

    // ESN
    proposal.extendedSequenceNumbers.buildTransform(
        PayloadType.TypeExtendedSequenceNumbers.value.toUByte(),
        ESNOption.ESN_NO.value.toUShort(),
        null,
        null,
        ByteArray(0)
    )

    // Traffic Selector
    val tsi = ikePayload.buildTrafficSelectorInitiator()
    tsi.trafficSelectors.buildIndividualTrafficSelector(
        TS_IPV4_ADDR_RANGE, 0u, 0u, 65535u,
        byteArrayOf(0, 0, 0, 0), byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))

    val tsr = ikePayload.buildTrafficSelectorResponder()
    tsr.trafficSelectors.buildIndividualTrafficSelector(
        TS_IPV4_ADDR_RANGE, 0u, 0u, 65535u,
        byteArrayOf(0, 0, 0, 0), byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))

    encryptProcedure(ue.n3iwfIkeSecurityAssociation, ikePayload, responseIKEMessage)

    // Send to N3IWF
    val ikeMessageData = responseIKEMessage.encode()
    log.trace("[handleIkeSaInit] [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

    val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
    ue.getUdpConn()!!.send(packet)

    ue.createHalfChildSA(
        ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID,
        ByteBuffer.wrap(inboundSPI).int.toUInt(),
        -1
    )
}


fun handleIKEAUTH(cfg: Config, ue: UeIke, ikeMsg: IKEMessage) {

    var encryptedPayload: Encrypted? = null

    if (ikeMsg.flags.toInt() != Flag.ResponseBitCheck.value.toInt()) {
        println("ikeMsg.Flags not equals to message.ResponseBitCheck")
        return
    }

    val localSPI = ikeMsg.responderSPI
    if (localSPI != ue.n3iwfIkeSecurityAssociation!!.remoteSPI) {
        println("Local SPI not equals to Remote SPI - N3IWF IKE Security Association")
        return
    }

    for (ikePayload in ikeMsg.payloads) {
        when (ikePayload.type()) {
            IKEPayloadType.TypeSK -> encryptedPayload = ikePayload as Encrypted
            else -> return
        }
    }

    val decryptedIKEPayload = decryptProcedure(ue.n3iwfIkeSecurityAssociation, ikeMsg, encryptedPayload)

    var eap: EAP? = null
    var securityAssociation: SecurityAssociation? = null
    var trafficSelectorInitiator: TrafficSelectorInitiator? = null
    var trafficSelectorResponder: TrafficSelectorResponder? = null
    var configuration: Configuration? = null
    val notifications = mutableListOf<Notification>()

    for (ikePayload in decryptedIKEPayload) {
        when (ikePayload.type()) {
            IKEPayloadType.TypeIDi -> ikePayload as IdentificationInitiator
            IKEPayloadType.TypeCERTreq -> ikePayload as CertificateRequest
            IKEPayloadType.TypeCERT -> ikePayload as Certificate
            IKEPayloadType.TypeSA -> securityAssociation = ikePayload as SecurityAssociation
            IKEPayloadType.TypeTSi -> trafficSelectorInitiator = ikePayload as TrafficSelectorInitiator
            IKEPayloadType.TypeTSr -> trafficSelectorResponder = ikePayload as TrafficSelectorResponder
            IKEPayloadType.TypeEAP -> eap = ikePayload as EAP
            IKEPayloadType.TypeAUTH -> ikePayload as Authentication
            IKEPayloadType.TypeCP -> configuration = ikePayload as Configuration
            IKEPayloadType.TypeN -> notifications.add(ikePayload as Notification)
            else -> {}
        }
    }

    // Completes the EAP-5G session
    if (eap != null && eap.code == EAPCode.EAPCodeSuccess.value) {
        ue.n3iwfIkeSecurityAssociation!!.state++
    }

    val ikePayload = IKEPayloadContainer()
    val responseIKEMessage = IKEMessage()

    when (ue.n3iwfIkeSecurityAssociation!!.state) {
        PreSignalling.toUByte() -> {
            ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID++

            responseIKEMessage.buildIKEHeader(
                ue.n3iwfIkeSecurityAssociation!!.localSPI,
                ue.n3iwfIkeSecurityAssociation!!.remoteSPI,
                ExchangeType.IKE_AUTH.value.toUByte(),
                Flag.InitiatorBitCheck.value.toUByte(),
                ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID
            )

            // EAP-5G vendor type data
            var eapVendorTypeData = ByteArray(2)
            eapVendorTypeData[0] = EAP5GType.EAP5GType5GNAS.value.toByte()

            // AN Parameters
            val anParameters = buildEAP5GANParameters(cfg)
            val anParametersLength = ByteBuffer.allocate(2).putShort(anParameters.size.toShort()).array()

            eapVendorTypeData += anParametersLength
            eapVendorTypeData += anParameters

            // Send Registration Request
            // create context for NAS signal
            val registrationRequest = buildRegistrationRequest(ue.nasContext)
            val nasLength = ByteArray(2)
            ByteBuffer.wrap(nasLength).putShort(registrationRequest.size.toShort())

            eapVendorTypeData += nasLength
            eapVendorTypeData += registrationRequest

            // EAP
            val eapResponse = ikePayload.buildEAP(EAPCode.EAPCodeResponse.value, eap!!.identifier)
            eapResponse.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), eapVendorTypeData)

            encryptProcedure(ue.n3iwfIkeSecurityAssociation, ikePayload, responseIKEMessage)

            // change the IKE state to EAP signalling
            ue.n3iwfIkeSecurityAssociation!!.state++

            val ikeMessageData = responseIKEMessage.encode()
            log.trace("Send ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

            // Send to N3IWF
            val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
            ue.getUdpConn()!!.send(packet)
        }


        EAPSignalling.toUByte() -> {
            // receive EAP/NAS messages
            // get NAS data
            val eapExpanded = eap!!.eapTypeData[0] as? EAPExpanded ?: run {
                println("[UE][IKE][EAP][NAS] Error in receive EAP/NAS messages")
                return
            }
            val nasData = eapExpanded.vendorData.copyOfRange(4, eapExpanded.vendorData.size)

            // handle NAS message
            val responseNas = dispatchNas(nasData, ue.nasContext!!)

            ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID++

            responseIKEMessage.buildIKEHeader(
                ue.n3iwfIkeSecurityAssociation!!.localSPI,
                ue.n3iwfIkeSecurityAssociation!!.remoteSPI,
                ExchangeType.IKE_AUTH.value.toUByte(),
                Flag.InitiatorBitCheck.value.toUByte(),
                ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID
            )

            // EAP-5G vendor type data
            var eapVendorTypeData = ByteArray(4)
            eapVendorTypeData[0] = EAP5GType.EAP5GType5GNAS.value.toByte()

            // NAS messages
            val nasLength = ByteArray(2)
            ByteBuffer.wrap(nasLength).putShort(responseNas!!.size.toShort())

            eapVendorTypeData += nasLength
            eapVendorTypeData += responseNas

            // EAP
            val eapResponse = ikePayload.buildEAP(EAPCode.EAPCodeResponse.value, eap.identifier)
            eapResponse.eapTypeData.buildEAPExpanded(VendorID3GPP.toUInt(), VendorTypeEAP5G.toUInt(), eapVendorTypeData)

            log.trace("eapVendorTypeData[${eapVendorTypeData.size}] = ${eapVendorTypeData.toUByteArrayString()}")
            encryptProcedure(ue.n3iwfIkeSecurityAssociation, ikePayload, responseIKEMessage)

            val ikeMessageData = responseIKEMessage.encode()
            log.trace("Send ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

            // Send to N3IWF
            val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
            ue.getUdpConn()!!.send(packet)
        }


        PostSignalling.toUByte() -> {

            // handling establishment of the IPsec tunnel
            ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID++

            responseIKEMessage.buildIKEHeader(
                ue.n3iwfIkeSecurityAssociation!!.localSPI,
                ue.n3iwfIkeSecurityAssociation!!.remoteSPI,
                ExchangeType.IKE_AUTH.value.toUByte(),
                Flag.InitiatorBitCheck.value.toUByte(),
                ue.n3iwfIkeSecurityAssociation!!.initiatorMessageID
            )

            // Authentication
            ikePayload.buildAuthentication(SignatureType.SharedKeyMesageIntegrityCode.value.toByte(), byteArrayOf(1, 2, 3))

            val configurationRequest = ikePayload.buildConfiguration(ConfigurationMessageType.CFG_REQUEST.value.toByte())
            configurationRequest.configurationAttribute.buildConfigurationAttribute(ConfigurationAttributeType.INTERNAL_IP4_ADDRESS.value.toUShort(), ByteArray(0))

            encryptProcedure(ue.n3iwfIkeSecurityAssociation, ikePayload, responseIKEMessage)

            val ikeMessageData = responseIKEMessage.encode()
            log.trace("Send ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

            // Send to N3IWF
            val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
            ue.getUdpConn()!!.send(packet)

            // change the IKE state to TCPEstablishSignalling
            ue.n3iwfIkeSecurityAssociation!!.state++
        }


        TCPEstablishSignalling.toUByte() -> {

            // security association
            ue.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA = securityAssociation

            // notification
            for (notification in notifications) {
                when (notification.notifyMessageType) {
                    Vendor3GPPNotifyTypeNAS_IP4_ADDRESS -> {
                        ue.n3iwfNasAddr.IP = ue.n3iwfNasAddr.IP.iPv4(notification.notificationData[0], notification.notificationData[1], notification.notificationData[2], notification.notificationData[3])
                    }
                    Vendor3GPPNotifyTypeNAS_TCP_PORT -> {
                        ue.n3iwfNasAddr.port = ByteBuffer.wrap(notification.notificationData).short.toInt()
                    }
                }
            }

            if (configuration!!.configurationType.toInt() == ConfigurationMessageType.CFG_REPLY.value.toInt()) {
                for (configAttr in configuration.configurationAttribute.attributes) {
                    when (configAttr.type) {
                        ConfigurationAttributeType.INTERNAL_IP4_ADDRESS.value.toUShort() -> ue.ueAddr.ip = IP.newIP(configAttr.value)
                        ConfigurationAttributeType.INTERNAL_IP4_NETMASK.value.toUShort() -> ue.ueAddr.mask = IPMask.newIPMask(configAttr.value)
                    }
                }
            }

            val outboundSPI = ByteBuffer.wrap(ue.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA!!.proposals[0].spi).int

            val childSecurityAssociationContext = ue.completeChildSA(0x01u, outboundSPI.toUInt(), ue.n3iwfIkeSecurityAssociation!!.ikeAuthResponseSA)

            parseIPAddressInformationToChildSecurityAssociation(
                childSecurityAssociationContext,
                trafficSelectorInitiator!!.trafficSelectors[0],
                trafficSelectorResponder!!.trafficSelectors[0],
                ue, "tcp"
            )

            generateKeyForChildSA(ue.n3iwfIkeSecurityAssociation!!, childSecurityAssociationContext)

            GlobalScope.launch {
                Ipsec().run(cfg, ue.ueAddr, childSecurityAssociationContext, ue.n3iwfNasAddr, ue)
            }
        }
    }
}


fun handleCreateChildSa(cfg: Config, ue: UeIke, ikeMsg: IKEMessage) {

    var encryptedPayload: Encrypted? = null

    val localSPI = ikeMsg.responderSPI
    if (localSPI != ue.n3iwfIkeSecurityAssociation!!.remoteSPI) {
        println("[UE][IKE] Error in IKE header: $localSPI")
        return
    }

    for (ikePayload in ikeMsg.payloads) {
        when (ikePayload.type()) {
            IKEPayloadType.TypeSK -> encryptedPayload = ikePayload as Encrypted
            else -> return
        }
    }

    val decryptedIkePayload = decryptProcedure(ue.n3iwfIkeSecurityAssociation, ikeMsg, encryptedPayload)

    // Parse payloads
    var securityAssociation: SecurityAssociation? = null
    var trafficSelectorInitiator: TrafficSelectorInitiator? = null
    var trafficSelectorResponder: TrafficSelectorResponder? = null
    var outboundSPI: UInt = 0u

    for (ikePayloadType in decryptedIkePayload) {
        when (ikePayloadType.type()) {
            IKEPayloadType.TypeSA -> {
                securityAssociation = ikePayloadType as SecurityAssociation
                outboundSPI = ByteBuffer.wrap(securityAssociation.proposals[0].spi).order(ByteOrder.BIG_ENDIAN).int.toUInt()
            }
            IKEPayloadType.TypeNiNr -> {
                val responseNonce = ikePayloadType as Nonce
                ue.n3iwfIkeSecurityAssociation!!.concatenatedNonce = responseNonce.nonceData
            }
            IKEPayloadType.TypeTSi -> {
                trafficSelectorInitiator = ikePayloadType as TrafficSelectorInitiator
            }
            IKEPayloadType.TypeTSr -> {
                trafficSelectorResponder = ikePayloadType as TrafficSelectorResponder
            }
            IKEPayloadType.TypeN -> {
                val notification = ikePayloadType as Notification
                if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyType5G_QOS_INFO.toInt()) {
                    val info = parse5GQoSInfoNotify(notification)
                    ue.qosInfo = info
                }
                if (notification.notifyMessageType.toInt() == Vendor3GPPNotifyTypeUP_IP4_ADDRESS.toInt()) {
                    ue.n3iwfUpAddr = IP.newIP(notification.notificationData.copyOfRange(0, 4))
                }
            }
            else -> {}
        }
    }

    val responseIKEMessage = IKEMessage()
    val ikePayload = IKEPayloadContainer()

    // handling establishment of the IPsec Child SA
    ue.n3iwfIkeSecurityAssociation!!.responderMessageID = ikeMsg.messageID

    responseIKEMessage.buildIKEHeader(
        ue.n3iwfIkeSecurityAssociation!!.localSPI,
        ue.n3iwfIkeSecurityAssociation!!.remoteSPI,
        ExchangeType.CREATE_CHILD_SA.value.toUByte(),
        (Flag.ResponseBitCheck.value.toInt() or Flag.InitiatorBitCheck.value.toInt()).toUByte(),
        ue.n3iwfIkeSecurityAssociation!!.responderMessageID
    )

    // SA
    val inboundSPI = ue.generateSPI()
    securityAssociation!!.proposals[0].spi = inboundSPI
    ikePayload.add(securityAssociation)

    // TSi
    ikePayload.add(trafficSelectorInitiator!!)

    // TSr
    ikePayload.add(trafficSelectorResponder!!)

    // Nonce
    val localNonce = generateRandomNumber().toByteArray()
    ue.n3iwfIkeSecurityAssociation!!.concatenatedNonce += localNonce
    ikePayload.buildNonce(localNonce)
    encryptProcedure(ue.n3iwfIkeSecurityAssociation!!, ikePayload, responseIKEMessage)

    val ikeMessageData = responseIKEMessage.encode()
    log.trace("Send ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())
    // Envia 428

    // Send to N3IWF
    val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
    ue.getUdpConn()!!.send(packet)

    ue.createHalfChildSA(
        ue.n3iwfIkeSecurityAssociation!!.responderMessageID,
        ByteBuffer.wrap(inboundSPI).int.toUInt(),
        -1
    )

    val childSecurityAssociationContextUserPlane = ue.completeChildSA(
        ue.n3iwfIkeSecurityAssociation!!.responderMessageID,
        outboundSPI,
        securityAssociation
    )

    parseIPAddressInformationToChildSecurityAssociation(
        childSecurityAssociationContextUserPlane,
        trafficSelectorResponder.trafficSelectors[0],
        trafficSelectorInitiator.trafficSelectors[0],
        ue,
        "gre"
    )

    generateKeyForChildSA(ue.n3iwfIkeSecurityAssociation!!, childSecurityAssociationContextUserPlane)

    // create GRE tunnel
    GlobalScope.launch {
        Gre.run(
            cfg,
            ue.ueAddr,
            ue.n3iwfUpAddr,
            childSecurityAssociationContextUserPlane,
            ue,
            ue.qosInfo
        )
    }
}