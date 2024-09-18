package internal.nas.handler

import free5gc.nas.Message
import internal.nas.context.UeNas
import internal.nas.message.*
import pkg.metrics.UeMetrics
import java.time.Duration
import java.time.Instant


fun handlerAuthenticationRequest(ue: UeNas, message: Message): ByteArray {
    // check authentication message (RAND and AUTN)
    val rand = message.gmmMessage!!.authenticationRequest!!.authenticationParameterRAND!!.getRANDValue()
    val autn = message.gmmMessage!!.authenticationRequest!!.authenticationParameterAUTN!!.getAUTN()

    // getting RES*
    val (paramAutn, check) = ue.deriveRESstarAndSetKey(
        ue.nasSecurity.authenticationSubs!!,
        rand.toByteArray(),
        ue.nasSecurity.snn,
        autn.toByteArray()
    )

    val authenticationResponse: ByteArray = when (check) {
        "MAC failure" -> buildAuthenticationFailure("MAC failure", "", ByteArray(0))
        "SQN failure" -> getAuthenticationFailure("SQN failure", "", paramAutn!!)
        "successful" -> {
            val response = buildAuthenticationResponse(paramAutn!!, "")
            ue.authTime = Duration.between(ue.beginTime, Instant.now())
            UeMetrics().addAuthTime(ue.authTime.toMillis())
            response
        }
        else -> ByteArray(0)
    }

    // sending to IKE stack
    return authenticationResponse
}


fun handlerSecurityModeCommand(ue: UeNas, message: Message): ByteArray {
    // TODO check security Mode Command Message
    // getting NAS Security Mode Complete
    val securityModeComplete = buildSecurityModeComplete(ue)

    // ipsec is operational, send the message in envelope
    ue.securityTime = Duration.between(ue.beginTime, Instant.now())
    UeMetrics().addSecurityTime(ue.securityTime.toMillis())

    // sending to IKE stack
    return securityModeComplete
}


fun handlerRegistrationAccept(ue: UeNas, message: Message): ByteArray {
    // change the state of UE to registered
    ue.setRegistered()

    // getting NAS Registration Complete
    val registrationComplete = buildRegistrationComplete(ue)

    ue.registerTime = Duration.between(ue.beginTime, Instant.now())
    UeMetrics().addRegisterTime(ue.registerTime.toMillis())

    return registrationComplete
}


fun handlerDlNasTransportPduaccept(ue: UeNas, message: Message): ByteArray? {
    // set the IP of PDU Session to UE
    ue.pduSession.pduAddress = getPduAddressFromPduEstablishmentAccept(message)
    ue.setPduSessionActive()
    ue.pduTime = Duration.between(ue.beginTime, Instant.now())

    UeMetrics().addPduTime(ue.pduTime.toMillis())

    return null
}