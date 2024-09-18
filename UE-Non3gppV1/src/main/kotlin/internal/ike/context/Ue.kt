package internal.ike.context

import engine.util.EnvironmentSetting
import go.net.IP
import go.net.IPNet
import go.net.TCPAddr
import internal.ike.context.RandomNumberGenerator.generateRandomNumber
import internal.ike.message.*
import java.math.BigInteger
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.time.Instant

class UeIke {
    var n3iwfIp: String = ""
    var ueIp: String = ""
    var udpConn: DatagramSocket? = null
    var ikeSecurity: IkeSecurity = IkeSecurity()
    var n3iwfChildSecurityAssociation: MutableMap<ULong, ChildSecurityAssociation> = mutableMapOf()
    var secret: BigInteger? = null
    var factor: BigInteger? = null
    var localNonce: ByteArray = byteArrayOf()
    var n3iwfIkeSecurityAssociation: IkeSecurityAssociation? = null
    var nasContext: internal.nas.context.UeNas? = null
    var temporaryExchangeMsgIdChildSAMapping: MutableMap<ULong, ChildSecurityAssociation> = mutableMapOf()
    var qosInfo: PDUQoSInfo? = null
    var n3iwfNasAddr: TCPAddr = TCPAddr()
    var n3iwfUpAddr: IP = IP()
    var ueAddr: IPNet = IPNet()
    var beginTime: Instant = Instant.now()
    var ipsecTime: Duration = Duration.ZERO

    var n3iwfUdp: InetSocketAddress? = null


    companion object {
        fun newUeIke(ueNas: internal.nas.context.UeNas): UeIke {
            val ue = UeIke()
            ue.newDiffieHellmanGroup(true)
            ue.newEncryptionAlgorithm(true)
            ue.newPseudorandomFunction(true)
            ue.newIntegrityAlgorithm(true)
            ue.nasContext = ueNas
            return ue
        }
    }


    fun terminate() {
        // close IKE socket udp
        udpConn?.close()

        // clean xfrm policy and states
        EnvironmentSetting().xfrmPolicyFlush()
        EnvironmentSetting().xfrmStateFlush()
    }

    fun createN3IWFIKESecurityAssociation(ikeSecurity: IkeSecurityAssociation?) {
        this.n3iwfIkeSecurityAssociation = ikeSecurity
        this.n3iwfIkeSecurityAssociation?.state = 0u // pre-signaling
    }

    fun newEncryptionAlgorithm(encryptionAlgorithm1: Boolean) {
        if (encryptionAlgorithm1) {
            this.ikeSecurity.encryptionAlgorithm = EncryptionAlgorithm.ENCR_AES_CBC.value.toUShort()
        }
    }

    fun newPseudorandomFunction(pseudorandomFunction1: Boolean) {
        if (pseudorandomFunction1) {
            this.ikeSecurity.pseudorandomFunction = PRFAlgorithm.PRF_HMAC_SHA1.value.toUShort()
        }
    }

    fun newDiffieHellmanGroup(diffieHellmanGroup1: Boolean) {
        if (diffieHellmanGroup1) {
            this.ikeSecurity.diffieHellmanGroup = DiffieHellmanGroup.DH_2048_BIT_MODP.value.toUShort()
        }
    }

    fun newIntegrityAlgorithm(integrityFunction1: Boolean) {
        if (integrityFunction1) {
            this.ikeSecurity.integrityAlgorithm = AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toUShort()
        }
    }

    fun getIntegrityAlgorithm(): UShort {
        return this.ikeSecurity.integrityAlgorithm
    }

    fun getDiffieHellmanGroup(): UShort {
        return this.ikeSecurity.diffieHellmanGroup
    }

    fun getPseudorandomFunction(): UShort {
        return this.ikeSecurity.pseudorandomFunction
    }

    fun getEncryptionAlgorithm(): UShort {
        return this.ikeSecurity.encryptionAlgorithm
    }

    @JvmName("getUdpConn-ike")
    fun getUdpConn(): DatagramSocket? {
        return this.udpConn
    }

    @JvmName("setUdpConn-ike")
    fun setUdpConn(conn: DatagramSocket) {
        this.udpConn = conn
    }

    fun generateSPI(): ByteArray {
        val spi: UInt
        val spiByte = ByteArray(4)
        while (true) {
            val randomUint64 = generateRandomNumber().toLong().toULong()

            if (!this.n3iwfChildSecurityAssociation.containsKey(randomUint64)) {
                spi = randomUint64.toUInt()
                ByteBuffer.wrap(spiByte).putInt(spi.toInt())
                break
            }
        }
        return spiByte
    }

    @JvmName("setSecret-ike")
    fun setSecret(secret: BigInteger) {
        this.secret = secret
    }

    @JvmName("getSecret-ike")
    fun getSecret(): BigInteger? {
        return this.secret
    }

    @JvmName("setFactor-ike")
    fun setFactor(factor: BigInteger) {
        this.factor = factor
    }

    @JvmName("getFactor-ike")
    fun getFactor(): BigInteger? {
        return this.factor
    }

    @JvmName("setLocalNonce-ike")
    fun setLocalNonce(localNonce: ByteArray) {
        this.localNonce = localNonce
    }

    @JvmName("getLocalNonce-ike")
    fun getLocalNonce(): ByteArray {
        return this.localNonce
    }

    @JvmName("setN3iwfIp-ike")
    fun setN3iwfIp(ip: String) {
        this.n3iwfIp = ip
    }

    @JvmName("getN3iwfIp-ike")
    fun getN3iwfIp(): String {
        return this.n3iwfIp
    }

    fun setUEIp(ip: String) {
        this.ueIp = ip
    }

    @JvmName("getUeIp-ike")
    fun getUeIp(): String {
        return this.ueIp
    }

    fun createHalfChildSA(msgID: UInt, inboundSPI: UInt, pduSessionID: Long) {
        val childSA = ChildSecurityAssociation()
        childSA.inboundSPI = inboundSPI
        childSA.pduSessionIds.add(pduSessionID)
        // Map Exchange Message ID and Child SA data until get paired response
        this.temporaryExchangeMsgIdChildSAMapping[msgID.toULong()] = childSA
    }


    fun completeChildSA(msgID: UInt, outboundSPI: UInt, chosenSecurityAssociation: SecurityAssociation?): ChildSecurityAssociation {
        val childSA = temporaryExchangeMsgIdChildSAMapping[msgID.toULong()]
            ?: throw Exception("There's not a half child SA created by the exchange with message ID $msgID.")

        // Remove mapping of exchange msg ID and child SA
        temporaryExchangeMsgIdChildSAMapping.remove(msgID.toULong())

        if (chosenSecurityAssociation == null) {
            throw Exception("chosenSecurityAssociation is null")
        }

        if (chosenSecurityAssociation.proposals.isEmpty()) {
            throw Exception("No proposal")
        }

        childSA.outboundSPI = outboundSPI

        if (chosenSecurityAssociation.proposals[0].encryptionAlgorithm.transforms.isNotEmpty()) {
            childSA.encryptionAlgorithm = chosenSecurityAssociation.proposals[0].encryptionAlgorithm.transforms[0].transformID
        }
        if (chosenSecurityAssociation.proposals[0].integrityAlgorithm.transforms.isNotEmpty()) {
            childSA.integrityAlgorithm = chosenSecurityAssociation.proposals[0].integrityAlgorithm.transforms[0].transformID
        }
        if (chosenSecurityAssociation.proposals[0].extendedSequenceNumbers.transforms.isNotEmpty()) {
            childSA.esn = chosenSecurityAssociation.proposals[0].extendedSequenceNumbers.transforms[0].transformID.toInt() != 0
        }

        // Record to UE context with inbound SPI as key
        n3iwfChildSecurityAssociation[childSA.inboundSPI.toULong()] = childSA
        return childSA
    }
}


class IkeSecurity {
    var encryptionAlgorithm: UShort = 0u
    var pseudorandomFunction: UShort = 0u
    var integrityAlgorithm: UShort = 0u
    var diffieHellmanGroup: UShort = 0u
}

class ChildSecurityAssociation {
    // SPI
    var inboundSPI: UInt = 0u
    var outboundSPI: UInt = 0u

    // Associated XFRM interface
    var xfrmIface: String = ""

    // IP address
    var peerPublicIpAddr: IP? = null
    var localPublicIpAddr: IP? = null

    // Traffic selector
    var selectedIPProtocol: UByte = 0u
    var trafficSelectorLocal: IPNet? = null
    var trafficSelectorRemote: IPNet? = null

    // Security
    var encryptionAlgorithm: UShort = 0u
    var initiatorToResponderEncryptionKey: ByteArray = byteArrayOf()
    var responderToInitiatorEncryptionKey: ByteArray = byteArrayOf()
    var integrityAlgorithm: UShort = 0u
    var initiatorToResponderIntegrityKey: ByteArray = byteArrayOf()
    var responderToInitiatorIntegrityKey: ByteArray = byteArrayOf()
    var esn: Boolean = false

    // Encapsulate
    var enableEncapsulate: Boolean = false
    var n3iwfPort: Int = 0
    var natPort: Int = 0

    // PDU Session IDs associated with this child SA
    var pduSessionIds: MutableList<Long> = mutableListOf()
}

class PDUQoSInfo {
    var pduSessionID: UByte = 0u
    var qfiList: ByteArray = ByteArray(0)
    var isDefault: Boolean = false
    var isDSCPSpecified: Boolean = false
    var dscp: UByte = 0u
}