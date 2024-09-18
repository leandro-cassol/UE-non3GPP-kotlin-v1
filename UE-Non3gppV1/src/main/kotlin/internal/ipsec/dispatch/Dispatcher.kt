package internal.ipsec.dispatch

import internal.ipsec.context.UeIpSec
import internal.ipsec.handler.handlerPDUSession
import internal.ipsec.handler.handlerRegisteredInitiated
import internal.nas.context.*


fun dispatch(ue: UeIpSec, msg: ByteArray) {
    // Decap NAS message from envelope
    val nasMsg = ue.decapNasPduFromEnvelope(msg)

    when (ue.nasContext!!.stateMM) {
        RegisteredInitiated.toInt() -> {
            handlerRegisteredInitiated(ue, nasMsg)
        }
        Registered.toInt() -> {
            when (ue.nasContext!!.stateSM) {
                PduSessionInactive.toInt() -> {
                    // Handle inactive PDU session state if needed
                }
                PduSessionPending.toInt() -> {
                    handlerPDUSession(ue, nasMsg)
                }
                PduSessionActive.toInt() -> {
                    // Handle active PDU session state if needed
                }
            }
        }
    }
}
