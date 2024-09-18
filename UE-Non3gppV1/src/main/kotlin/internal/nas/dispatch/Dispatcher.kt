package internal.nas.dispatch

import free5gc.nas.Message
import free5gc.nas.Message.Companion.MsgTypeAuthenticationReject
import free5gc.nas.Message.Companion.MsgTypeAuthenticationRequest
import free5gc.nas.Message.Companion.MsgTypeConfigurationUpdateCommand
import free5gc.nas.Message.Companion.MsgTypeDLNASTransport
import free5gc.nas.Message.Companion.MsgTypeIdentityRequest
import free5gc.nas.Message.Companion.MsgTypeRegistrationAccept
import free5gc.nas.Message.Companion.MsgTypeRegistrationReject
import free5gc.nas.Message.Companion.MsgTypeSecurityModeCommand
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtected
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedAndCiphered
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext
import free5gc.nas.SecurityHeader.Companion.SecurityHeaderTypePlainNas
import free5gc.nas.getSecurityHeaderType
import free5gc.nas.security.BearerNon3GPP
import free5gc.nas.security.DirectionDownlink
import free5gc.nas.security.nasEncrypt
import free5gc.nas.security.nasMacCalculate
import internal.nas.context.UeNas
import internal.nas.handler.handlerAuthenticationRequest
import internal.nas.handler.handlerDlNasTransportPduaccept
import internal.nas.handler.handlerRegistrationAccept
import internal.nas.handler.handlerSecurityModeCommand


fun dispatchNas(message: ByteArray, ue: UeNas): ByteArray? {
    // check if message is null
    if (message.isEmpty()) {
        throw IllegalArgumentException("[UE][NAS] NAS message is null")
    }

    // decode NAS message
    val m = Message()
    m.securityHeader.securityHeaderType = getSecurityHeaderType(message) and 0x0fu

    var payload = message

    // check if NAS is security protected
    if (m.securityHeader.securityHeaderType != SecurityHeaderTypePlainNas) {

        // sequence number
        val sequenceNumber = payload[6]

        // mac verification
        val macReceived = payload.sliceArray(2..5)

        // remove security header except for sequence number
        payload = payload.sliceArray(6 until payload.size)

        // check security header type
        val cph = when (m.securityHeader.securityHeaderType) {
            SecurityHeaderTypeIntegrityProtected -> {
                false
            }
            SecurityHeaderTypeIntegrityProtectedAndCiphered -> {
                true
            }
            SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext -> {
                ue.nasSecurity.dlCount.set(0u, 0u)
                false
            }
            SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext -> {
                ue.nasSecurity.dlCount.set(0u, 0u)
                true
            }
            else -> false
        }

        // check security header (Downlink data)
        if (ue.nasSecurity.dlCount.sqn() > sequenceNumber.toUByte()) {
            ue.nasSecurity.dlCount.setOverflow((ue.nasSecurity.dlCount.overflow().toInt() + 1).toUShort())
        }
        ue.nasSecurity.dlCount.setSQN(sequenceNumber.toUByte())

        val mac32 = nasMacCalculate(
                ue.nasSecurity.integrityAlg,
                ue.nasSecurity.knasInt,
                ue.nasSecurity.dlCount.get(),
                BearerNon3GPP,
                DirectionDownlink,
                payload
            )

        // check integrity
        if (!mac32.contentEquals(macReceived)) {
            return null
        }

        // check ciphering
        if (cph) {
            nasEncrypt(
                ue.nasSecurity.cipheringAlg,
                ue.nasSecurity.knasEnc.toByteArray(),
                ue.nasSecurity.dlCount.get(),
                BearerNon3GPP,
                DirectionDownlink,
                payload.sliceArray(1 until payload.size)
            )
        }

        // remove security header
        payload = message.sliceArray(7 until message.size)

        // decode NAS message
        m.plainNasDecode(payload)

    } else {
        // decode NAS message without security header
        m.plainNasDecode(payload)
    }

    return when (m.gmmMessage!!.gmmHeader.getMessageType()) {
        MsgTypeAuthenticationRequest -> handlerAuthenticationRequest(ue, m)
        MsgTypeAuthenticationReject -> null // handler.HandlerAuthenticationReject(ue, m)
        MsgTypeIdentityRequest -> null // handler identity request.
        MsgTypeSecurityModeCommand -> handlerSecurityModeCommand(ue, m)
        MsgTypeRegistrationAccept -> handlerRegistrationAccept(ue, m)
        MsgTypeConfigurationUpdateCommand -> null // handler Configuration Update Command.
        MsgTypeDLNASTransport -> handlerDlNasTransportPduaccept(ue, m)
        MsgTypeRegistrationReject -> null // handler registration reject
        else -> null
    }
}
