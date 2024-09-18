package internal.ike.trigger

import engine.util.removeZero
import engine.util.strToByteArray
import engine.util.toBigInteger
import engine.util.toUByteArrayString
import internal.ike.context.RandomNumberGenerator.generateRandomNumber
import internal.ike.context.UeIke
import internal.ike.context.group14Generator
import internal.ike.message.*
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.net.DatagramPacket

private val log = LoggerFactory.getLogger("InitRegistration")


fun initRegistration(ue: UeIke) {

    // IKE_SA_INIT
    val ikeInitiatorSPI: ULong = 123123u
    val ikeMessage = IKEMessage()

    ikeMessage.buildIKEHeader(
        ikeInitiatorSPI,
        0u,
        ExchangeType.IKE_SA_INIT.value.toUByte(),
        Flag.InitiatorBitCheck.value.toUByte(),
        0u
    )

    // Security Association
    val securityAssociation = ikeMessage.payloads.buildSecurityAssociation()

    // Proposal 1
    val proposal = securityAssociation.proposals.buildProposal(1u, ProtocolType.TypeIKE.value.toUByte(), ByteArray(0))

    val attributeType: UShort = AttributeType.AttributeTypeKeyLength.value.toUShort()
    val keyLength: UShort = 256u

    // ENCR
    proposal.encryptionAlgorithm.buildTransform(
        PayloadType.TypeEncryptionAlgorithm.value.toUByte(),
        EncryptionAlgorithm.ENCR_AES_CBC.value.toUShort(),
        attributeType,
        keyLength,
        ByteArray(0)
    )

    // INTEG
    proposal.integrityAlgorithm.buildTransform(
        PayloadType.TypeIntegrityAlgorithm.value.toUByte(),
        AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toUShort(),
        null,
        null,
        ByteArray(0)
    )

    // PRF
    proposal.pseudorandomFunction.buildTransform(
        PayloadType.TypePseudorandomFunction.value.toUByte(),
        PRFAlgorithm.PRF_HMAC_SHA1.value.toUShort(),
        null,
        null,
        ByteArray(0)
    )

    // DH
    proposal.diffieHellmanGroup.buildTransform(
        PayloadType.TypeDiffieHellmanGroup.value.toUByte(),
        DiffieHellmanGroup.DH_2048_BIT_MODP.value.toUShort(),
        null,
        null,
        ByteArray(0)
    )

    // Key exchange data
    val generator = BigInteger.valueOf(group14Generator.toLong())

    //val factor = BigInteger(engine.exchange.pkg.ike.handler.group14PrimeString, 16)
    // Ao usar group14PrimeString, estava gerando um BigInteger de 257 Bytes.
    // Assim, o BigInteger a partir dos Bytes gerados na execução do UE em GO
    val factorByteArray = strToByteArray("255 255 255 255 255 255 255 255 201 15 218 162 33 104 194 52 196 198 98 139 128 220 28 209 41 2 78 8 138 103 204 116 2 11 190 166 59 19 155 34 81 74 8 121 142 52 4 221 239 149 25 179 205 58 67 27 48 43 10 109 242 95 20 55 79 225 53 109 109 81 194 69 228 133 181 118 98 94 126 198 244 76 66 233 166 55 237 107 11 255 92 182 244 6 183 237 238 56 107 251 90 137 159 165 174 159 36 17 124 75 31 230 73 40 102 81 236 228 91 61 194 0 124 184 161 99 191 5 152 218 72 54 28 85 211 154 105 22 63 168 253 36 207 95 131 101 93 35 220 163 173 150 28 98 243 86 32 133 82 187 158 213 41 7 112 150 150 109 103 12 53 78 74 188 152 4 241 116 108 8 202 24 33 124 50 144 94 70 46 54 206 59 227 158 119 44 24 14 134 3 155 39 131 162 236 7 162 143 181 197 93 240 111 76 82 201 222 43 203 246 149 88 23 24 57 149 73 124 234 149 106 229 21 210 38 24 152 250 5 16 21 114 142 90 138 172 170 104 255 255 255 255 255 255 255 255")
    val factor = factorByteArray.toBigInteger()
    val secret = generateRandomNumber()

    val valAux = generator.modPow(secret, factor)
    val localPublicKeyExchangeValue: ByteArray = valAux.toByteArray().removeZero()

    val prependZero = ByteArray(factor.toByteArray().size - localPublicKeyExchangeValue.size)
    var localPublicKeyExchangeValuePadded = prependZero + localPublicKeyExchangeValue
    localPublicKeyExchangeValuePadded = localPublicKeyExchangeValuePadded.removeZero()

    ikeMessage.payloads.buildKeyExchange(DiffieHellmanGroup.DH_2048_BIT_MODP.value.toShort(), localPublicKeyExchangeValuePadded)

    // stored secret and factor
    ue.setFactor(factor)
    ue.setSecret(secret)

    // Nonce
    val localNonce = generateRandomNumber().toByteArray()

    ue.setLocalNonce(localNonce)
    ikeMessage.payloads.buildNonce(localNonce)

    // Send to N3IWF
    val ikeMessageData = ikeMessage.encode()
    log.trace("Send ikeMessageData [${ikeMessageData.size}] " + ikeMessageData.toUByteArrayString())

    val packet = DatagramPacket(ikeMessageData, ikeMessageData.size, ue.n3iwfUdp)
    ue.getUdpConn()!!.send(packet)
}