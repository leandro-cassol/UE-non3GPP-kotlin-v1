package internal.ike.message

import config.Config
import org.slf4j.LoggerFactory
import pkg.utils.Utils

// IMPLEMENTADO NO ARQUIVO MESSAGE.KT

private val log = LoggerFactory.getLogger("ike.message")


fun buildEAP5GANParameters(cfg: Config): ByteArray {
    var anParameters = byteArrayOf()

    // [TS 24.502] 9.3.2.2.2.3
    // AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
    // Therefore, IEI of AN-parameter is not needed to be included.

    // anParameter = AN-parameter Type | AN-parameter Length | Value part of IE

    // Build GUAMI
    val resu = Utils().getMccAndMncInOctets(cfg.ue.hplmn.mcc, cfg.ue.hplmn.mnc)

    var anParameter = ByteArray(2)

    val guami = ByteArray(6)
    guami[0] = Utils().convertToHexByte(Utils().parseUint8ToHexadecimal(resu[0].toUByte())) // 0x02
    guami[1] = Utils().convertToHexByte(Utils().parseUint8ToHexadecimal(resu[1].toUByte())) // 0xf8
    guami[2] = Utils().convertToHexByte(Utils().parseUint8ToHexadecimal(resu[2].toUByte())) // 0x39

    guami[3] = Utils().convertToHexByte(cfg.ue.amfId.region)  // 0xca
    guami[4] = Utils().convertToHexByte(cfg.ue.amfId.set)     // 0xfe
    guami[5] = Utils().convertToHexByte(cfg.ue.amfId.pointer) // 0x0

    anParameter[0] = ANParametersType.ANParametersTypeGUAMI.value.toByte()
    anParameter[1] = guami.size.toByte()
    anParameter += guami

    anParameters += anParameter

    // Build Establishment Cause
    anParameter = ByteArray(2)
    val establishmentCause = byteArrayOf(EstablishmentCause.EstablishmentCauseMO_Signalling.value.toByte())
    anParameter[0] = ANParametersType.ANParametersTypeEstablishmentCause.value.toByte()
    anParameter[1] = establishmentCause.size.toByte()
    anParameter += establishmentCause

    anParameters += anParameter

    // Build PLMN ID
    log.info("Build PLMN ID - Init")
    anParameter = ByteArray(2)
    val plmnID = ByteArray(3)
    plmnID[0] = Utils().convertToHexByte(Utils().parseUint8ToHexadecimal(resu[0].toUByte())) // 0x02
    plmnID[1] = Utils().convertToHexByte(Utils().parseUint8ToHexadecimal(resu[1].toUByte())) // 0xf8
    plmnID[2] = resu[2] // 0x39

    anParameter[0] = ANParametersType.ANParametersTypeSelectedPLMNID.value.toByte()
    anParameter[1] = plmnID.size.toByte()
    anParameter += plmnID

    anParameters += anParameter

    // Validate Length Field
    Utils().validateLenStringField("Snssai - SD", cfg.ue.snssai.sd, 6u)

    val snssaiSdUm = cfg.ue.snssai.sd.substring(0, 2)
    val snssaiSdDois = cfg.ue.snssai.sd.substring(2, 4)
    val snssaiSdTres = cfg.ue.snssai.sd.substring(4, 6)

    // Build NSSAI
    anParameter = ByteArray(2)
    var nssai = byteArrayOf()

    // s-nssai = s-nssai length(1 byte) | SST(1 byte) | SD(3 bytes)
    val snssai = ByteArray(5)
    snssai[0] = 4
    snssai[1] = cfg.ue.snssai.sst.toByte()
    snssai[2] = Utils().convertToHexByte(snssaiSdUm)
    snssai[3] = Utils().convertToHexByte(snssaiSdDois)
    snssai[4] = Utils().convertToHexByte(snssaiSdTres)

    nssai += snssai

    anParameter[0] = ANParametersType.ANParametersTypeRequestedNSSAI.value.toByte()
    anParameter[1] = nssai.size.toByte()
    anParameter += nssai

    anParameters += anParameter

    return anParameters
}