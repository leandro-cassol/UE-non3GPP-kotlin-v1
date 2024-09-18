package internal.nas.context

import engine.util.EnvironmentSetting
import free5gc.nas.nasType.MobileIdentity5GS
import free5gc.nas.security.AlgCiphering128NEA0
import free5gc.nas.security.AlgIntegrity128NIA2
import free5gc.nas.security.Count
import free5gc.openapi.models.*
import free5gc.util.ueauth.*
import go.net.IP
import org.slf4j.LoggerFactory
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Duration
import java.time.Instant
import kotlin.experimental.xor


private val log = LoggerFactory.getLogger("UeNas")

const val RegisteredInitiated: UInt = 0u
const val Registered: UInt = 1u

const val PduSessionInactive: UInt = 0u
const val PduSessionPending: UInt = 1u
const val PduSessionActive: UInt = 2u


class PDUSession {
    var id: UByte = 0u
    var snssai: Snssai = Snssai(0, "")
    var dnn: String = ""
    var pduAddress: IP = IP()
    var greInterface: String = ""
    var route: String = ""


    companion object {
        fun newPDUSession(id: UByte, sst: Int, sd: String, dnn: String): PDUSession {
            val pduSession = PDUSession()
            pduSession.id = id
            pduSession.snssai = Snssai(sst, sd)
            pduSession.dnn = dnn
            return pduSession
        }
    }
}


class NasSecurity {
    var ranUeNgapId: Long = 0
    var amfUeNgapId: Long = 0
    var msin: String = ""
    var mcc: String = ""
    var mnc: String = ""
    var supi: String = ""
    var ulCount: Count = Count(0u)
    var dlCount: Count = Count(0u)
    var cipheringAlg: UByte = 0u
    var integrityAlg: UByte = 0u
    var snn: String = ""
    var knasEnc: UByteArray = UByteArray(16)
    var knasInt: UByteArray = UByteArray(16)
    var kamf: UByteArray = UByteArray(0)
    var authenticationSubs: AuthenticationSubscription? = null
    var suci: MobileIdentity5GS = MobileIdentity5GS()
    var guti: ByteArray = ByteArray(4)
    var anType: AccessType? = null

    companion object {
        fun newNasSecurity(
            msin: String, mcc: String, mnc: String, ranUeNgapId: Long,
            cipheringAlg: UByte, integrityAlg: UByte,
            anType: AccessType, k: String, opc: String, op: String, amf: String, sqn: String
        ): NasSecurity {
            val nasSecurity = NasSecurity()
            nasSecurity.msin = msin
            nasSecurity.mcc = mcc
            nasSecurity.mnc = mnc
            nasSecurity.ranUeNgapId = ranUeNgapId
            nasSecurity.cipheringAlg = cipheringAlg
            nasSecurity.integrityAlg = integrityAlg
            nasSecurity.anType = anType
            nasSecurity.authenticationSubs = setAuthSubscription(k, opc, op, amf, sqn)
            nasSecurity.snn = deriveSNN(mcc, mnc)
            nasSecurity.supi = "imsi-$mcc$mnc$msin"
            return nasSecurity
        }
    }
}

class ArgumentsNas {
    var mcc: String = ""
    var mnc: String = ""
    var msin: String = ""
    var ranUeNgapId: Long = 0
    var k: String = ""
    var opc: String = ""
    var op: String = ""
    var amf: String = ""
    var sqn: String = ""
    var sst: Int = 0
    var sd: String = ""
    var dnn: String = ""
}


class UeNas {
    var id: UByte = 0u
    var stateMM: Int = 0
    var stateSM: Int = 0
    var pduSession: PDUSession = PDUSession()
    var nasSecurity: NasSecurity = NasSecurity()
    var xfrmInterface: String = ""
    var tcpIpsec: Socket? = null
    var beginTime: Instant = Instant.now()
    var registerTime: Duration = Duration.ZERO
    var pduTime: Duration = Duration.ZERO
    var securityTime: Duration = Duration.ZERO
    var authTime: Duration = Duration.ZERO


    companion object {
        fun newUeNas(argsNas: ArgumentsNas): UeNas {
            val ueNas = UeNas()
            ueNas.id = 1u
            ueNas.stateMM = RegisteredInitiated.toInt()
            ueNas.stateSM = PduSessionInactive.toInt()

            ueNas.nasSecurity = NasSecurity.newNasSecurity(argsNas.msin,
                argsNas.mcc, argsNas.mnc, argsNas.ranUeNgapId,
                AlgCiphering128NEA0, AlgIntegrity128NIA2,
                AccessType.AccessType_NON_3_GPP_ACCESS, argsNas.k,
                argsNas.opc, argsNas.op, argsNas.amf, argsNas.sqn)

            ueNas.pduSession = PDUSession.newPDUSession(1u, argsNas.sst, argsNas.sd, argsNas.dnn)
            ueNas.beginTime = Instant.now()
            return ueNas
        }
    }


    fun terminate() {
        EnvironmentSetting().linkDel(this.xfrmInterface)
        this.tcpIpsec?.close()
        EnvironmentSetting().linkDel(this.pduSession.greInterface)
        EnvironmentSetting().routeDel(this.xfrmInterface, this.pduSession.route)
        EnvironmentSetting().routeDelDefault()
    }

    fun setRegistered() {
        stateMM = Registered.toInt()
    }

    fun setGRERoute(route: String) {
        pduSession.route = route
    }

    fun setGREInterface(greInterface: String) {
        pduSession.greInterface = greInterface
    }

    @JvmName("setXfrmInterface-ipsec")
    fun setXfrmInterface(xfrmInterface: String) {
        this.xfrmInterface = xfrmInterface
    }

    @JvmName("getXfrmInterface-ipsec")
    fun getXfrmInterface(): String {
        return xfrmInterface
    }

    fun setIpsecTcp(tcpSocket: Socket) {
        tcpIpsec = tcpSocket
    }

    fun getIpsecTcp(): Socket? = tcpIpsec

    fun setPduSessionPending() {
        stateSM = PduSessionPending.toInt()
    }

    fun setPduSessionActive() {
        stateSM = PduSessionActive.toInt()
    }


    fun deriveRESstarAndSetKey(authSubs: AuthenticationSubscription, rand: ByteArray, snName: String, autn: ByteArray): Pair<ByteArray?, String> {
        // parameters for authentication challenge.
        val macA = ByteArray(8)
        val macS = ByteArray(8)
        val ck = ByteArray(16)
        val ik = ByteArray(16)
        val res = ByteArray(8)
        val ak = ByteArray(6)
        val akStar = ByteArray(6)

        // Get OPC, K, SQN, AMF from USIM.
        val opc = authSubs.opc!!.opcValue.hexStringToByteArray()
        val k = authSubs.permanentKey!!.permanentKeyValue.hexStringToByteArray()
        val sqnUe = authSubs.sequenceNumber.hexStringToByteArray()
        val amf = authSubs.authenticationManagementField.hexStringToByteArray()

        // Generate RES, CK, IK, AK, AKstar
        free5gc.util.milenage.f2345(opc, k, rand, res, ck, ik, ak, akStar)

        // Get SQN, MAC_A, AMF from AUTN
        val (sqnHn, _, macAHn) = deriveAUTN(autn, ak)

        // Generate MAC_A, MAC_S
        free5gc.util.milenage.f1(opc, k, rand, sqnHn, amf, macA, macS)

        // MAC verification
        if (!macA.contentEquals(macAHn)) {
            return Pair(null, "MAC failure")
        }

        if (compareByteArrays(sqnUe, sqnHn) > 0) {
            free5gc.util.milenage.f2345(opc, k, rand, res, ck, ik, ak, akStar)

            // From the standard, AMF(0x0000) should be used in the synch failure.
            val amfSynch = "0000".hexStringToByteArray()

            // get mac_s using sqn ue
            free5gc.util.milenage.f1(opc, k, rand, sqnUe, amfSynch, macA, macS)

            val sqnUeXorAK = ByteArray(6)
            for (i in sqnUe.indices) {
                sqnUeXorAK[i] = sqnUe[i] xor akStar[i]
            }

            val failureParam = sqnUeXorAK + macS
            return Pair(failureParam, "SQN failure")
        }

        // updated sqn value.
        authSubs.sequenceNumber = sqnHn.toHexString()

        // derive RES*
        val key = ck + ik
        val fc = FC_FOR_RES_STAR_XRES_STAR_DERIVATION
        val p0 = snName.toByteArray()
        val p1 = rand
        val p2 = res
        derivateKamf(key, snName, sqnHn, ak)
        derivateAlgKey()
        val kdfValForResStar = getKdfValue(key, fc, p0, kdfLen(p0), p1, kdfLen(p1), p2, kdfLen(p2))
        val result = kdfValForResStar.copyOfRange(kdfValForResStar.size / 2, kdfValForResStar.size)
        return Pair(result, "successful")
    }


    private fun derivateKamf(key: ByteArray, snName: String, sqn: ByteArray, ak: ByteArray) {
        val fc = FC_FOR_KAUSF_DERIVATION
        var p0 = snName.toByteArray()
        val sqnXorAK = ByteArray(6)
        for (i in sqn.indices) {
            sqnXorAK[i] = (sqn[i] xor ak[i])
        }
        var p1 = sqnXorAK
        val kausf = getKdfValue(key, fc, p0, kdfLen(p0), p1, kdfLen(p1))

        p0 = snName.toByteArray()
        val kseaf = getKdfValue(kausf, FC_FOR_KSEAF_DERIVATION, p0, kdfLen(p0))

        val supiRegexp = Regex("(?:imsi|supi)-([0-9]{5,15})")
        val groups = supiRegexp.find(nasSecurity.supi)?.groupValues

        p0 = groups!![1].toByteArray()
        val l0 = kdfLen(p0)
        p1 = byteArrayOf(0x00, 0x00)
        val l1 = kdfLen(p1)
        nasSecurity.kamf = getKdfValue(kseaf, FC_FOR_KAMF_DERIVATION, p0, l0, p1, l1).toUByteArray()
    }


    private fun derivateAlgKey() {
        var p0 = byteArrayOf(free5gc.nas.security.NNASEncAlg.toByte())
        var l0 = kdfLen(p0)
        var p1 = byteArrayOf(nasSecurity.cipheringAlg.toByte())
        var l1 = kdfLen(p1)
        val kenc = getKdfValue(nasSecurity.kamf.toByteArray(), FC_FOR_ALGORITHM_KEY_DERIVATION, p0, l0, p1, l1)
        nasSecurity.knasEnc = kenc.copyOfRange(16, 32).toUByteArray()

        p0 = byteArrayOf(free5gc.nas.security.NNASIntAlg.toByte())
        l0 = kdfLen(p0)
        p1 = byteArrayOf(nasSecurity.integrityAlg.toByte())
        l1 = kdfLen(p1)
        val kint = getKdfValue(nasSecurity.kamf.toByteArray(), FC_FOR_ALGORITHM_KEY_DERIVATION, p0, l0, p1, l1)
        nasSecurity.knasInt = kint.copyOfRange(16, 32).toUByteArray()
    }


    private fun deriveAUTN(autn: ByteArray, ak: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val sqn = ByteArray(6)

        // get SQNxorAK
        val sqnXorAK = autn.sliceArray(0..5)
        val amf = autn.sliceArray(6..7)
        val macA = autn.sliceArray(8 until autn.size)

        // get SQN
        for (i in sqnXorAK.indices) {
            sqn[i] = sqnXorAK[i] xor ak[i]
        }

        // return SQN, amf, mac_a
        return Triple(sqn, amf, macA)
    }


    fun deriveKn3iwf(): ByteArray? {
        val p0 = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(nasSecurity.ulCount.get().toInt() - 1).array()
        val l0 = kdfLen(p0)
        val p1 = byteArrayOf(free5gc.nas.security.AccessTypeNon3GPP.toByte())
        val l1 = kdfLen(p1)

        return try {
            getKdfValue(
                nasSecurity.kamf.toByteArray(),
                FC_FOR_KGNB_KN3IWF_DERIVATION,
                p0,
                l0,
                p1,
                l1
            )
        } catch (e: Exception) {
            log.error("Error occurs when Get KDF Value: $e")
            null
        }
    }


    private fun String.hexStringToByteArray(): ByteArray {
        val len = length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }


    // Função para comparar dois arrays de bytes lexicograficamente
    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val length = minOf(a.size, b.size)
        for (i in 0 until length) {
            if (a[i] != b[i]) {
                return a[i].compareTo(b[i])
            }
        }
        return a.size.compareTo(b.size)
    }


    // Extension function to convert ByteArray to hex string
    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

}


fun setAuthSubscription(k: String, opcVal: String, opVal: String, amf: String, sqn: String): AuthenticationSubscription {
    return AuthenticationSubscription().apply {
        permanentKey = PermanentKey().apply { permanentKeyValue = k}
        opc = Opc().apply { opcValue = opcVal}

        milenage = Milenage().apply {
            op = Op().apply {
                opValue = opVal
            }
        }
        authenticationManagementField = amf
        sequenceNumber = sqn
        authenticationMethod = AuthMethod.AuthMethod__5_G_AKA
    }
}


fun deriveSNN(mcc: String, mnc: String): String {
    // 5G:mnc093.mcc208.3gppnetwork.org
    return if (mnc.length == 2) {
        "5G:mnc0$mnc.mcc$mcc.3gppnetwork.org"
    } else {
        "5G:mnc$mnc.mcc$mcc.3gppnetwork.org"
    }
}