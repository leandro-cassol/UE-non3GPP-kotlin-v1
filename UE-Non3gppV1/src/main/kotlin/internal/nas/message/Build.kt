package internal.nas.message

import free5gc.nas.Message
import free5gc.nas.Message.Companion.MsgTypePDUSessionEstablishmentAccept
import free5gc.nas.SecurityHeader
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedAndCiphered
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext
import free5gc.nas.nasMessage.CommInfoIE.Companion.RegistrationType5GSInitialRegistration
import free5gc.nas.nasMessage.CommInfoIE.Companion.ULNASTransportRequestTypeInitialRequest
import free5gc.nas.nasMessage.Epd5GSMobilityManagementMessage
import free5gc.nas.nasMessage.RegistrationRequest
import free5gc.nas.nasMessage.RegistrationRequest.Companion.RegistrationRequestCapability5GMMType
import free5gc.nas.nasType.Capability5GMM
import free5gc.nas.nasType.MobileIdentity5GS
import free5gc.nas.security.BearerNon3GPP
import free5gc.nas.security.DirectionUplink
import go.net.IP
import internal.nas.context.UeNas
import org.slf4j.LoggerFactory
import pkg.utils.Utils


private val log = LoggerFactory.getLogger("Security")


fun getPduAddressFromPduEstablishmentAccept(message: Message): IP {
    val container = getNasPduAcceptFromDlNasTransport(message)
    if (container.gsmMessage?.gsmHeader?.getMessageType() == MsgTypePDUSessionEstablishmentAccept) {
        // get UE ip
        val ueIp = container.gsmMessage!!.pduSessionEstablishmentAccept!!.pduAddress!!.getPDUAddressInformation()
        return IP().iPv4(ueIp[0].toByte(), ueIp[1].toByte(), ueIp[2].toByte(), ueIp[3].toByte())
    }
    throw Exception("IP = NULL")
}


fun buildSecurityModeComplete(ue: UeNas?): ByteArray {
    val registrationRequest = buildRegistrationRequest(ue!!)
    val securityModeComplete = getSecurityModeComplete(registrationRequest)
    val securityModeCompleteWithSecurityHeader = encodeNasPduWithSecurity(
        ue,
        securityModeComplete,
        SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext.toByte(),
       true,
       true
    )
    return securityModeCompleteWithSecurityHeader
}


fun buildRegistrationComplete(ue: UeNas?): ByteArray {
    val registrationComplete = getRegistrationComplete(null)
    val registrationCompleteWithSecurityHeader = encodeNasPduWithSecurity(
        ue,
        registrationComplete,
        SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext.toByte(),
        true,
        true
    )
    return registrationCompleteWithSecurityHeader
}


fun buildAuthenticationFailure(cause: String, eapMsg: String, paramAutn: ByteArray): ByteArray {
    return getAuthenticationFailure(cause, eapMsg, paramAutn)
}


fun buildAuthenticationResponse(paramAutn: ByteArray, eapMsg: String): ByteArray {
    return getAuthenticationResponse(eapMsg, paramAutn)
}


fun buildRegistrationRequest(ue: UeNas?): ByteArray {
    log.info("Build Registration Request")
    // get mcc and mcc
    val resu = Utils().getMccAndMncInOctets(ue!!.nasSecurity.mcc, ue.nasSecurity.mnc)
    log.info("Mcc and Mnc In Octets: $resu")

    // get msin
    val (suciV1, suciV2, suciV3, suciV4, suciV5) = Utils().encodeUeSuci(ue.nasSecurity.msin)

    val suci = if (ue.nasSecurity.msin.length == 8) {
        MobileIdentity5GS().apply {
            len = 12u
            buffer = ubyteArrayOf(0x01u, resu[0].toUByte(), resu[1].toUByte(), resu[2].toUByte(),
                0xf0u, 0xffu, 0x00u, 0x00u, suciV4.toUByte(), suciV3.toUByte(), suciV2.toUByte(), suciV1.toUByte())
        }
    } else {
        MobileIdentity5GS().apply {
            len = 13u
            buffer = ubyteArrayOf(0x01u, resu[0].toUByte(), resu[1].toUByte(), resu[2].toUByte(),
                0xf0u, 0xffu, 0x00u, 0x00u, suciV5.toUByte(), suciV4.toUByte(), suciV3.toUByte(), suciV2.toUByte(), suciV1.toUByte())
        }
    }

    val capability5GMM = Capability5GMM.newCapability5GMM(RegistrationRequestCapability5GMMType)
    capability5GMM.len = 1u
    capability5GMM.octet = ubyteArrayOf(0x07u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u)


    return getRegistrationRequest(
        RegistrationType5GSInitialRegistration,
        suci,
        null,
        getUESecurityCapability(ue.nasSecurity.cipheringAlg, ue.nasSecurity.integrityAlg),
        capability5GMM,
        null,
        null
    )
}


fun buildPduEstablishmentRequest(ue: UeNas?): ByteArray {
    val ulNasPduRequestMessage = getUlNasTransport(
        ue!!.pduSession.id,
        ULNASTransportRequestTypeInitialRequest,
        ue.pduSession.dnn,
        ue.pduSession.snssai
    )

    val ulNasPduRequestMessageWithSecurityHeader = encodeNasPduWithSecurity(
        ue,
        ulNasPduRequestMessage,
        SecurityHeaderTypeIntegrityProtectedAndCiphered.toByte(),
        true, false
    )
    return ulNasPduRequestMessageWithSecurityHeader
}


fun getUESecurityCapability(cipheringAlg: UByte, integrityAlg: UByte): free5gc.nas.nasType.UESecurityCapability {
    val ueSecurityCapability = free5gc.nas.nasType.UESecurityCapability()
    ueSecurityCapability.iei = RegistrationRequest.RegistrationRequestUESecurityCapabilityType
    ueSecurityCapability.len = 2u
    ueSecurityCapability.buffer = (byteArrayOf(0x00, 0x00)).toUByteArray()
    when (cipheringAlg) {
        free5gc.nas.security.AlgCiphering128NEA0 -> ueSecurityCapability.setEA0_5G(1u)
        free5gc.nas.security.AlgCiphering128NEA1 -> ueSecurityCapability.setEA1_128_5G(1u)
        free5gc.nas.security.AlgCiphering128NEA2 -> ueSecurityCapability.setEA2_128_5G(1u)
        free5gc.nas.security.AlgCiphering128NEA3 -> ueSecurityCapability.setEA3_128_5G(1u)
    }
    when (integrityAlg) {
        free5gc.nas.security.AlgIntegrity128NIA0 -> ueSecurityCapability.setIA0_5G(1u)
        free5gc.nas.security.AlgIntegrity128NIA1 -> ueSecurityCapability.setIA1_128_5G(1u)
        free5gc.nas.security.AlgIntegrity128NIA2 -> ueSecurityCapability.setIA2_128_5G(1u)
        free5gc.nas.security.AlgIntegrity128NIA3 -> ueSecurityCapability.setIA3_128_5G(1u)
    }
    return ueSecurityCapability
}


fun encodeNasPduWithSecurity(ue: UeNas?, pdu: ByteArray, securityHeaderType: Byte,
                             securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {
    val m = Message.newMessage()
    m.plainNasDecode(pdu)

    val auxSecurityHeader = SecurityHeader()
    auxSecurityHeader.protocolDiscriminator = Epd5GSMobilityManagementMessage
    auxSecurityHeader.securityHeaderType = securityHeaderType.toUByte()
    m.securityHeader = auxSecurityHeader

    return nasEncode(ue, m, securityContextAvailable, newSecurityContext)
}


fun nasEncode(ue: UeNas?, msg: Message?, securityContextAvailable: Boolean, newSecurityContext: Boolean): ByteArray {
    var payload: ByteArray?
    val sequenceNumber: Byte

    if (ue == null) {
        throw Exception("amfUe is nil")
    }
    if (msg == null) {
        throw Exception("Nas Message is empty")
    }
    if (!securityContextAvailable) {
        payload = msg.plainNasEncode()
        return payload!!
    } else {
        if (newSecurityContext) {
            ue.nasSecurity.ulCount.set(0u, 0u)
            ue.nasSecurity.dlCount.set(0u, 0u)
        }
        sequenceNumber = ue.nasSecurity.ulCount.sqn().toByte()
        payload = msg.plainNasEncode()

        log.trace("payload [${payload!!.size}] = ${payload.toUByteArray().contentToString()}")

        free5gc.nas.security.nasEncrypt(
            ue.nasSecurity.cipheringAlg,
            ue.nasSecurity.knasEnc.toByteArray(),
            ue.nasSecurity.ulCount.get(),
            BearerNon3GPP,
            DirectionUplink,
            payload
        )

        log.trace("payload [${payload.size}] = ${payload.toUByteArray().contentToString()}")
        // add sequece number
        payload = byteArrayOf(sequenceNumber) + payload

        val mac32 = free5gc.nas.security.nasMacCalculate(
            ue.nasSecurity.integrityAlg,
            ue.nasSecurity.knasInt,
            ue.nasSecurity.ulCount.get(),
            BearerNon3GPP,
            DirectionUplink,
            payload
        )

        // Add mac value
        payload = mac32 + payload

        // Add EPD and Security Type
        val msgSecurityHeader = byteArrayOf(msg.securityHeader.protocolDiscriminator.toByte(), msg.securityHeader.securityHeaderType.toByte())
        payload = msgSecurityHeader + payload

        // Increase UL Count
        ue.nasSecurity.ulCount.addOne()
    }
    return payload
}