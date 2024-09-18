package internal.ipsec.handler

import internal.ipsec.context.UeIpSec
import internal.nas.dispatch.dispatchNas
import internal.nas.message.buildPduEstablishmentRequest

fun handlerRegisteredInitiated(ue: UeIpSec, msg: ByteArray) {
    // get registration complete/correct response
    val responseNas = dispatchNas(msg, ue.nasContext!!)

    // set the message as NAS envelope
    var envelope = ue.encapNasMsgToEnvelope(responseNas!!)

    // send registration complete/correct response
    val tcp = ue.getTcpConn()
    tcp!!.getOutputStream().write(envelope)

    // change the state of NAS messages
    ue.nasContext!!.setRegistered()

    // TODO investigates
    Thread.sleep(500)

    // send the pdu establishment request for establish the pdu session
    val pduRequest = buildPduEstablishmentRequest(ue.nasContext)

    // set the message as NAS envelope
    envelope = ue.encapNasMsgToEnvelope(pduRequest)

    // send PDU Session Request to N3IWF
    tcp.getOutputStream().write(envelope)

    // change the state of NAS messages
    ue.nasContext!!.setPduSessionPending()
}


fun handlerPDUSession(ue: UeIpSec, msg: ByteArray) {
    // get UE PDU Address Session
    dispatchNas(msg, ue.nasContext!!)
}