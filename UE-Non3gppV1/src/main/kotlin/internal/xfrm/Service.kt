package internal.xfrm

import config.Config
import engine.util.EnvironmentSetting
import go.net.IPNet
import go.netlink.*
import internal.ike.context.ChildSecurityAssociation
import internal.ike.message.AuthenticationAlgorithm
import internal.ike.message.EncryptionAlgorithm


enum class XFRMEncryptionAlgorithmType(val value: UInt) {
    DES(EncryptionAlgorithm.ENCR_DES.value),
    DES3(EncryptionAlgorithm.ENCR_3DES.value),
    CAST(EncryptionAlgorithm.ENCR_CAST.value),
    BLOWFISH(EncryptionAlgorithm.ENCR_BLOWFISH.value),
    NULL(EncryptionAlgorithm.ENCR_NULL.value),
    AES_CBC(EncryptionAlgorithm.ENCR_AES_CBC.value),
    AES_CTR(EncryptionAlgorithm.ENCR_AES_CTR.value);

    companion object {
        fun fromValue(value: UInt): XFRMEncryptionAlgorithmType? = entries.find { it.value == value }
    }

    override fun toString(): String {
        return when (this) {
            DES -> "cbc(des)"
            DES3 -> "cbc(des3_ede)"
            CAST -> "cbc(cast5)"
            BLOWFISH -> "cbc(blowfish)"
            NULL -> "ecb(cipher_null)"
            AES_CBC -> "cbc(aes)"
            AES_CTR -> "rfc3686(ctr(aes))"
        }
    }
}

enum class XFRMIntegrityAlgorithmType(val value: UInt) {
    HMAC_MD5_96(AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value),
    HMAC_SHA1_96(AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value),
    AES_XCBC_96(AuthenticationAlgorithm.AUTH_AES_XCBC_96.value);

    companion object {
        fun fromValue(value: UInt): XFRMIntegrityAlgorithmType? = entries.find { it.value == value }
    }


    override fun toString(): String {
        return when (this) {
            HMAC_MD5_96 -> "hmac(md5)"
            HMAC_SHA1_96 -> "hmac(sha1)"
            AES_XCBC_96 -> "xcbc(aes)"
        }
    }
}


fun applyXFRMRule(n3iwfIsInitiator: Boolean, xfrmiId: UInt, childSecurityAssociation: ChildSecurityAssociation) {

    // Build XFRM information data structure for incoming traffic.
    // Direction: N3IWF -> UE
    // State
    val xfrmEncryptionAlgorithm: XfrmStateAlgo
    var xfrmIntegrityAlgorithm = XfrmStateAlgo()
    if (n3iwfIsInitiator) {
        xfrmEncryptionAlgorithm = XfrmStateAlgo().apply {
            name = XFRMEncryptionAlgorithmType.fromValue(childSecurityAssociation.encryptionAlgorithm.toUInt()).toString()
            key = childSecurityAssociation.responderToInitiatorEncryptionKey
        }
        if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
            xfrmIntegrityAlgorithm = XfrmStateAlgo().apply {
                name = XFRMIntegrityAlgorithmType.fromValue(childSecurityAssociation.integrityAlgorithm.toUInt()).toString()
                key = childSecurityAssociation.responderToInitiatorIntegrityKey
            }
        }
    } else {
        xfrmEncryptionAlgorithm = XfrmStateAlgo().apply {
            name = XFRMEncryptionAlgorithmType.fromValue(childSecurityAssociation.encryptionAlgorithm.toUInt()).toString()
            key = childSecurityAssociation.initiatorToResponderEncryptionKey
        }
        if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
            xfrmIntegrityAlgorithm = XfrmStateAlgo().apply {
                name = XFRMIntegrityAlgorithmType.fromValue(childSecurityAssociation.integrityAlgorithm.toUInt()).toString()
                key = childSecurityAssociation.initiatorToResponderIntegrityKey
            }
        }
    }

    // State
    val xfrmState = XfrmState().apply {
        src = childSecurityAssociation.peerPublicIpAddr!!
        dst = childSecurityAssociation.localPublicIpAddr!!
        proto = Proto.XFRM_PROTO_ESP
        mode = Mode.XFRM_MODE_TUNNEL
        spi = childSecurityAssociation.inboundSPI
        ifid = xfrmiId.toInt()
        auth = xfrmIntegrityAlgorithm
        crypt = xfrmEncryptionAlgorithm
        esn = childSecurityAssociation.esn
        if (childSecurityAssociation.enableEncapsulate) {
            encap = XfrmStateEncap().apply {
                type = EncapType.XFRM_ENCAP_ESPINUDP
                srcPort = childSecurityAssociation.natPort
                dstPort = childSecurityAssociation.n3iwfPort
            }
        }
    }
    try {
        // Commit xfrm state to netlink
        xfrmStateAdd(xfrmState)
    } catch (err: Exception) {
        throw Exception("Set XFRM state rule failed: ${err.message}")
    }

    // Policy
    val xfrmPolicyTemplate = XfrmPolicyTmpl().apply {
        src = xfrmState.src
        dst = xfrmState.dst
        proto = xfrmState.proto
        mode = xfrmState.mode
        spi = xfrmState.spi
    }

    val xfrmPolicy = XfrmPolicy().apply {
        src = childSecurityAssociation.trafficSelectorRemote!!
        dst = childSecurityAssociation.trafficSelectorLocal!!
        proto = Proto.fromValue(childSecurityAssociation.selectedIPProtocol.toInt())!!
        dir = Dir.XFRM_DIR_IN
        ifid = xfrmiId.toInt()
        tmpls = listOf(xfrmPolicyTemplate)
    }

    try {
        // Commit xfrm policy to netlink
        xfrmPolicyAdd(xfrmPolicy)
    } catch (err: Exception) {
        throw Exception("Set XFRM policy rule failed: ${err.message}")
    }


    // Direction: UE -> N3IWF
    // State
    if (n3iwfIsInitiator) {
        xfrmEncryptionAlgorithm.key = childSecurityAssociation.initiatorToResponderEncryptionKey
        if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
            xfrmIntegrityAlgorithm.key = childSecurityAssociation.initiatorToResponderIntegrityKey
        }
    } else {
        xfrmEncryptionAlgorithm.key = childSecurityAssociation.responderToInitiatorEncryptionKey
        if (childSecurityAssociation.integrityAlgorithm.toInt() != 0) {
            xfrmIntegrityAlgorithm.key = childSecurityAssociation.responderToInitiatorIntegrityKey
        }
    }

    // State
    xfrmState.spi = childSecurityAssociation.outboundSPI
    xfrmState.src = childSecurityAssociation.localPublicIpAddr!!
    xfrmState.dst = childSecurityAssociation.peerPublicIpAddr!!

    xfrmState.encap?.let {
        val tmp = it.srcPort
        it.srcPort = it.dstPort
        it.dstPort = tmp
    }

    try {
        // Commit xfrm state to netlink
        xfrmStateAdd(xfrmState)
    } catch (err: Exception) {
        throw Exception("Set XFRM state rule failed: ${err.message}")
    }


    // Policy
    xfrmPolicyTemplate.spi = childSecurityAssociation.outboundSPI
    xfrmPolicyTemplate.src = xfrmState.src
    xfrmPolicyTemplate.dst = xfrmState.dst

    xfrmPolicy.src = childSecurityAssociation.trafficSelectorLocal!!
    xfrmPolicy.dst = childSecurityAssociation.trafficSelectorRemote!!
    xfrmPolicy.dir = Dir.XFRM_DIR_OUT
    xfrmPolicy.tmpls = listOf(xfrmPolicyTemplate)

    try {
        // Commit xfrm policy to netlink
        xfrmPolicyAdd(xfrmPolicy)
    } catch (err: Exception) {
        throw Exception("Set XFRM policy rule failed: ${err.message}")
    }
}


fun setupIpsecXfrmi(cfg: Config, parentIfaceName: String, xfrmIfaceId: UInt, xfrmIfaceAddr: IPNet): String {
    val newXfrmIName = "${cfg.ue.ipsecInterface.name}-default"

    EnvironmentSetting().linkAddXfrm(newXfrmIName, parentIfaceName, xfrmIfaceId.toInt(), cfg.ue.ipsecInterface.mtu)
    EnvironmentSetting().addrAdd(newXfrmIName, xfrmIfaceAddr.string())

    EnvironmentSetting().linkSetUp(newXfrmIName)

    return newXfrmIName
}