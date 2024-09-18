package internal.ipsec.context

import internal.nas.context.UeNas
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

class UeIpSec {
    var interfaceName: String = ""
    var tcpConn: Socket? = null
    var nasContext: UeNas? = null

    companion object {
        fun newUeIpSec(ueNas: UeNas, conn: Socket, intName: String): UeIpSec {
            val ueIpSec = UeIpSec()
            ueIpSec.tcpConn = conn
            ueIpSec.nasContext = ueNas
            ueIpSec.interfaceName = intName
            return ueIpSec
        }
    }

    @JvmName("getTcpConn-ipsec")
    fun getTcpConn(): Socket? {
        return this.tcpConn
    }

    @JvmName("setTcpConn-ipsec")
    fun setTcpConn(conn: Socket?) {
        this.tcpConn = conn
    }

    fun encapNasMsgToEnvelope(nasPDU: ByteArray): ByteArray {
        // According to TS 24.502 8.2.4,
        // in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
        // the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
        // According to TS 24.502 9.4,
        // a NAS message envelope = Length | NAS Message
        val nasEnv = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(nasPDU.size.toShort()).array() + nasPDU
        return nasEnv
    }

    fun decapNasPduFromEnvelope(envelope: ByteArray): ByteArray {
        // According to TS 24.502 8.2.4 and TS 24.502 9.4,
        // a NAS message envelope = Length | NAS Message
        if (envelope.size < 2) {
            throw IllegalArgumentException("NAS message envelope is less than 2 bytes")
        }

        // Get NAS Message Length
        val nasLen = ByteBuffer.wrap(envelope, 0, 2).short.toInt()
        if (envelope.size < 2 + nasLen) {
            throw IllegalArgumentException("NAS message envelope is less than the sum of 2 and nasLen")
        }

        // Extract NAS Message
        val nasMsg = envelope.copyOfRange(2, 2 + nasLen)
        return nasMsg
    }
}


