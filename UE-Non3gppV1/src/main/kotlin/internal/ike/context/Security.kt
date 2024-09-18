package internal.ike.context


import engine.util.toHexString
import engine.util.toUByteArrayString
import go.net.IP
import go.net.IPMask
import go.net.IPNet
import go.netlink.Proto
import internal.ike.message.*
import org.slf4j.LoggerFactory
import java.math.BigInteger
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and


private val log = LoggerFactory.getLogger("Security")


class IkeSecurityAssociation {
    // SPI
    var remoteSPI: ULong = 0u
    var localSPI: ULong = 0u

    // Message ID
    var initiatorMessageID: UInt = 0u
    var responderMessageID: UInt = 0u

    // Transforms for IKE SA
    var encryptionAlgorithm: Transform? = null
    var pseudorandomFunction: Transform? = null
    var integrityAlgorithm: Transform? = null
    var diffieHellmanGroup: Transform? = null
    var expandedSequenceNumber: Transform? = null

    // Used for key generating
    var concatenatedNonce: ByteArray = byteArrayOf()
    var diffieHellmanSharedKey: ByteArray = byteArrayOf()

    // Keys
    var skD: ByteArray = byteArrayOf()
    var skAi: ByteArray = byteArrayOf()
    var skAr: ByteArray = byteArrayOf()
    var skEi: ByteArray = byteArrayOf()
    var skEr: ByteArray = byteArrayOf()
    var skPi: ByteArray = byteArrayOf()
    var skPr: ByteArray = byteArrayOf()

    // State for IKE_AUTH
    var state: UByte = 0u

    // Temporary data stored for the use in later exchange
    var initiatorID: IdentificationInitiator? = null
    var initiatorCertificate: Certificate? = null
    var ikeAuthResponseSA: SecurityAssociation? = null
    var trafficSelectorInitiator: TrafficSelectorInitiator? = null
    var trafficSelectorResponder: TrafficSelectorResponder? = null
    var lastEapIdentifier: Byte = 0

    // Authentication data
    var localUnsignedAuthentication: ByteArray = byteArrayOf()
    var remoteUnsignedAuthentication: ByteArray = byteArrayOf()

    // NAT detection
    // If UEIsBehindNAT == true, N3IWF should enable NAT traversal and
    // TODO: should support dynamic updating network address (MOBIKE)
    var uEIsBehindNAT: Boolean = false
    // If N3IWFIsBehindNAT == true, N3IWF should send UDP keepalive periodically
    var n3iwfIsBehindNAT: Boolean = false
    //var thisUE: N3iwfUe? = null
}


object RandomNumberGenerator {
    private val randomNumberMaximum = BigInteger(String(CharArray(512) { 'F' }), 16)
    private val randomNumberMinimum = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val random: SecureRandom = SecureRandom()

    fun generateRandomNumber(): BigInteger {
        val random = SecureRandom()
        var number: BigInteger

        while (true) {
            val bytes = ByteArray(256)
            random.nextBytes(bytes)

            number = BigInteger(1, bytes)

            if (number > randomNumberMinimum && number < randomNumberMaximum) {
                break
            }
        }
        if (number.toByteArray().size == 256) {
            val randomInt64 = number.toInt()
            if (randomInt64 > 0) {
                return number
            }
        }
        return generateRandomNumber()
    }

    fun generateRandomUint8(): UByte {
        val number = ByteArray(1)
        random.nextBytes(number)
        return number[0].toUByte()
    }
}

// Diffie-Hellman Exchange
// The strength supplied by group 1 may not be sufficient for typical uses
const val group2PrimeString =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
        "C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6" +
        "F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE65381FFFFFFFFFFFFFFFF"
const val group2Generator = 2
const val group14PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
        "C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6" +
        "F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804" +
        "F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28F" +
        "B5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
const val group14Generator = 2


fun calculateDiffieHellmanMaterials(secret: BigInteger, peerPublicValue: ByteArray, diffieHellmanGroupNumber: UShort): Pair<ByteArray, ByteArray> {
    val peerPublicValueBig = BigInteger(peerPublicValue)
    val generator: BigInteger
    val factor: BigInteger
    when (diffieHellmanGroupNumber.toUInt()) {
        DiffieHellmanGroup.DH_1024_BIT_MODP.value -> {
            generator = BigInteger.valueOf(group2Generator.toLong())
            factor = BigInteger(group2PrimeString, 16)
        }
        DiffieHellmanGroup.DH_2048_BIT_MODP.value -> {
            generator = BigInteger.valueOf(group14Generator.toLong())
            factor = BigInteger(group14PrimeString, 16)
        }
        else -> {
            throw Exception("Unsupported Diffie-Hellman group: $diffieHellmanGroupNumber")
        }
    }
    var localPublicValue = generator.modPow(secret, factor).toByteArray()
    val prependZero = ByteArray(factor.toByteArray().size - localPublicValue.size)
    localPublicValue = prependZero + localPublicValue
    var sharedKey = peerPublicValueBig.modPow(secret, factor).toByteArray()
    val prependZero2 = ByteArray(factor.toByteArray().size - sharedKey.size)
    sharedKey = prependZero2 + sharedKey
    return Pair(localPublicValue, sharedKey)
}


// Pseudorandom Function
fun newPseudorandomFunction(key: ByteArray, algorithmType: UShort): Mac {
    return when (algorithmType.toUInt()) {
        PRFAlgorithm.PRF_HMAC_MD5.value -> {
            Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(key, "HmacMD5")) }
        }
        PRFAlgorithm.PRF_HMAC_SHA1.value -> {
            Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }
        }
        else -> {
            throw Exception("Unsupported pseudo random function: $algorithmType")
        }
    }
}

// Integrity Algorithm
fun calculateChecksum(key: ByteArray, originData: ByteArray, algorithmType: UShort): ByteArray {
    when (algorithmType.toUInt()) {
        AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> {
            if (key.size != 16) {
                throw Exception("Unmatched input key length")

            }
            val integrityFunction = Mac.getInstance("HmacMD5")
            val secretKey = SecretKeySpec(key, "HmacMD5")
            integrityFunction.init(secretKey)
            return integrityFunction.doFinal(originData)
        }
        AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> {
            if (key.size != 20) {
                throw Exception("Unmatched input key length")
            }
            val integrityFunction = Mac.getInstance("HmacSHA1")
            val secretKey = SecretKeySpec(key, "HmacSHA1")
            integrityFunction.init(secretKey)
            val result = integrityFunction.doFinal(originData)
            return Arrays.copyOfRange(result, 0, 12)
        }
        else -> {
            log.error("Unsupported integrity function: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

fun verifyIKEChecksum(key: ByteArray, originData: ByteArray, checksum: ByteArray, algorithmType: UShort): Boolean {
    return when (algorithmType.toUInt()) {
        AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> {
            if (key.size != 16) {
                throw Exception ("Unmatched input key length")
            } else {
                val integrityFunction = Mac.getInstance("HmacMD5").apply { init(SecretKeySpec(key, "HmacMD5")) }
                integrityFunction.update(originData)
                val checksumOfMessage = integrityFunction.doFinal()
                log.trace("Calculated checksum:\n${checksumOfMessage.toHexString()}\nReceived checksum:\n${checksum.toHexString()}")
                checksumOfMessage.contentEquals(checksum)
            }
        }
        AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> {
            if (key.size != 20) {
                throw Exception("Unmatched input key length")
            } else {
                val integrityFunction = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key, "HmacSHA1")) }
                integrityFunction.update(originData)
                val checksumOfMessage = integrityFunction.doFinal().copyOf(12)
                checksumOfMessage.contentEquals(checksum)
            }
        }
        else -> {
            log.error("Unsupported integrity function: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

// Encryption Algorithm
fun encryptMessage(key: ByteArray, originData: ByteArray, algorithmType: UShort): ByteArray {
    log.trace("encryptMessage")

    when (algorithmType.toUInt()) {
        EncryptionAlgorithm.ENCR_AES_CBC.value -> {

            // Criando um Cipher para criptografia usando AES/CBC/PKCS5Padding
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

            // Padding message
            val originPaddingData = pkcs7Padding(originData, cipher.blockSize)

            // Subtract 1 from the last element of the padded data
            originPaddingData[originPaddingData.size - 1]--

            // Vetor de Inicialização (IV) de 16 bytes
            val initializationVector = ByteArray(cipher.blockSize)
            SecureRandom().nextBytes(initializationVector)

            // Criando uma chave secreta AES 32 bytes (256 bits)
            val block = SecretKeySpec(key, "AES")

            // Inicializando o Cipher para criptografia com a chave e IV
            cipher.init(Cipher.ENCRYPT_MODE, block, IvParameterSpec(initializationVector))

            // Criptografando os dados
            val cipherText = ByteArray(originPaddingData.size + cipher.blockSize)
            cipher.doFinal(originPaddingData, 0, originPaddingData.size, cipherText, 0)

            val result = initializationVector + cipherText.copyOfRange(0, originPaddingData.size)
            log.trace("encryptMessage = [${result.size}] " + result.toUByteArrayString())

            return result
        }
        else -> {
            log.error("Unsupported encryption algorithm: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}


fun decryptMessage(key: ByteArray, cipherText: ByteArray, algorithmType: UShort): ByteArray {
    return when (algorithmType.toUInt()) {
        EncryptionAlgorithm.ENCR_AES_CBC.value -> {
            if (cipherText.size < 16) {
                throw Exception("Length of cipher text is too short to decrypt")
            }

            val initializationVector = cipherText.copyOfRange(0, 16)
            val encryptedMessage = cipherText.copyOfRange(16, cipherText.size)

            if (encryptedMessage.size % 16 != 0) {
                throw Exception("Cipher text is not a multiple of block size")
            }

            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val secretKey = SecretKeySpec(key, "AES")
            val ivParameterSpec = IvParameterSpec(initializationVector)

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
            val decryptedMessage = cipher.doFinal(encryptedMessage)
            val padding = decryptedMessage[decryptedMessage.size - 1].toInt() + 1
            Arrays.copyOfRange(decryptedMessage, 0, decryptedMessage.size - padding)
        }
        else -> {
            log.error("Unsupported encryption algorithm: $algorithmType")
            throw Exception("Unsupported algorithm")
        }
    }
}

private fun pkcs7Padding(data: ByteArray, blockSize: Int): ByteArray {
    val padding = blockSize - (data.size % blockSize)
    val paddedData = ByteArray(data.size + padding)
    System.arraycopy(data, 0, paddedData, 0, data.size)
    for (i in data.size until paddedData.size) {
        paddedData[i] = padding.toByte()
    }
    return paddedData
}


// Key Gen for IKE SA
fun generateKeyForIKESA(ikeSecurityAssociation: IkeSecurityAssociation) {
    val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction

    val lengthSKd = 20
    val lengthSKai = 20
    val lengthSKar = lengthSKai
    val lengthSKei = 32
    val lengthSKer = lengthSKei
    val lengthSKpi = lengthSKd
    val lengthSKpr = lengthSKd
    val totalKeyLength = lengthSKd + lengthSKai + lengthSKar + lengthSKei + lengthSKer + lengthSKpi + lengthSKpr

    log.trace("totalKeyLength = $totalKeyLength")
    log.trace("ikeSecurityAssociation.concatenatedNonce [${ikeSecurityAssociation.concatenatedNonce.size}] " + ikeSecurityAssociation.concatenatedNonce.toUByteArrayString())
    log.trace("transformPseudorandomFunction!!.transformID = ${transformPseudorandomFunction!!.transformID}")

    var pseudorandomFunction: Mac
    try {
        pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.concatenatedNonce, transformPseudorandomFunction.transformID)
    } catch (e: Exception) {
        throw Exception("New pseudorandom function failed")
    }

    pseudorandomFunction.update(ikeSecurityAssociation.diffieHellmanSharedKey)
    val sKeySeed = pseudorandomFunction.doFinal()

    log.trace("sKeySeed [${sKeySeed.size}] " + sKeySeed.toUByteArrayString())

    val seed = concatenateNonceAndSPI(
        ikeSecurityAssociation.concatenatedNonce,
        ikeSecurityAssociation.localSPI,
        ikeSecurityAssociation.remoteSPI
    )


    val localSpiArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(ikeSecurityAssociation.localSPI.toLong()).array()
    val remoteSPIArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(ikeSecurityAssociation.remoteSPI.toLong()).array()

    log.trace("ikeSecurityAssociation.concatenatedNonce [${ikeSecurityAssociation.concatenatedNonce.size}] " + ikeSecurityAssociation.concatenatedNonce.toUByteArrayString())
    log.trace("localSPI [${localSpiArray.size}] " + localSpiArray.toUByteArrayString())
    log.trace("remoteSPIArray [${remoteSPIArray.size}] " + remoteSPIArray.toUByteArrayString())
    log.trace("seed [${seed.size}] " + seed.toUByteArrayString())


    var keyStream = ByteArray(0)
    var generatedKeyBlock = ByteArray(0)
    var index = 1.toByte()
    while (keyStream.size < totalKeyLength) {
        try {
            pseudorandomFunction = newPseudorandomFunction(sKeySeed, transformPseudorandomFunction.transformID)
            pseudorandomFunction.update(generatedKeyBlock + seed + index)
            generatedKeyBlock = pseudorandomFunction.doFinal()
            keyStream += generatedKeyBlock
        } catch (e: Exception) {
            throw Exception("Pseudorandom function write failed")
        }
        index++
    }

    log.trace("keyStream [${keyStream.size}] " + keyStream.toUByteArrayString())

    ikeSecurityAssociation.skD = keyStream.copyOfRange(0, lengthSKd)
    keyStream = keyStream.drop(lengthSKd).toByteArray()
    ikeSecurityAssociation.skAi = keyStream.copyOfRange(0, lengthSKai)
    keyStream = keyStream.drop(lengthSKai).toByteArray()
    ikeSecurityAssociation.skAr = keyStream.copyOfRange(0, lengthSKar)
    keyStream = keyStream.drop(lengthSKar).toByteArray()
    ikeSecurityAssociation.skEi = keyStream.copyOfRange(0, lengthSKei)
    keyStream = keyStream.drop(lengthSKei).toByteArray()
    ikeSecurityAssociation.skEr = keyStream.copyOfRange(0, lengthSKer)
    keyStream = keyStream.drop(lengthSKer).toByteArray()
    ikeSecurityAssociation.skPi = keyStream.copyOfRange(0, lengthSKpi)
    keyStream = keyStream.drop(lengthSKpi).toByteArray()
    ikeSecurityAssociation.skPr = keyStream.copyOfRange(0, lengthSKpr)
    //keyStream = keyStream.drop(lengthSKpr).toByteArray()

    log.trace("ikeSecurityAssociation.skEi [${ikeSecurityAssociation.skEi.size}] " + ikeSecurityAssociation.skEi.toUByteArrayString())
}


fun generateKeyForChildSA(ikeSecurityAssociation: IkeSecurityAssociation, childSecurityAssociation: ChildSecurityAssociation) {
    // Transforms
    val transformPseudorandomFunction = ikeSecurityAssociation.pseudorandomFunction
    var transformIntegrityAlgorithmForIPSec: Transform? = null

        if (ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].integrityAlgorithm.transforms.size != 0) {
        transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.ikeAuthResponseSA!!.proposals[0].integrityAlgorithm.transforms[0]
    }

    // Get key length for encryption and integrity key for IPSec
    val lengthEncryptionKeyIPSec = 32
    val lengthIntegrityKeyIPSec = if (transformIntegrityAlgorithmForIPSec != null) 20 else 0
    val totalKeyLength = (lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec) * 2

    // Generate key for child security association as specified in RFC 7296 section 2.17
    val seed = ikeSecurityAssociation.concatenatedNonce
    var pseudorandomFunction: Mac

    var keyStream = byteArrayOf()
    var generatedKeyBlock = byteArrayOf()
    var index: Byte = 1

    while (keyStream.size < totalKeyLength) {
        pseudorandomFunction = newPseudorandomFunction(ikeSecurityAssociation.skD, transformPseudorandomFunction!!.transformID)
        pseudorandomFunction.update(appendArrays(generatedKeyBlock, seed, byteArrayOf(index)))
        generatedKeyBlock = pseudorandomFunction.doFinal()
        keyStream += generatedKeyBlock
        index++
    }
    childSecurityAssociation.initiatorToResponderEncryptionKey += keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

    childSecurityAssociation.initiatorToResponderIntegrityKey += keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthIntegrityKeyIPSec, keyStream.size)

    childSecurityAssociation.responderToInitiatorEncryptionKey += keyStream.copyOfRange(0, lengthEncryptionKeyIPSec)
    keyStream = keyStream.copyOfRange(lengthEncryptionKeyIPSec, keyStream.size)

    childSecurityAssociation.responderToInitiatorIntegrityKey += keyStream.copyOfRange(0, lengthIntegrityKeyIPSec)
}


// Decrypt
fun decryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation?, ikeMessage: IKEMessage?, encryptedPayload: Encrypted?): IKEPayloadContainer {
    log.trace("DecryptProcedure")
    val transformIntegrityAlgorithm = ikeSecurityAssociation!!.integrityAlgorithm
    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    val checksumLength = 12 // HMAC_SHA1_96

    // Checksum
    val checksum = encryptedPayload!!.encryptedData.sliceArray(encryptedPayload.encryptedData.size - checksumLength until encryptedPayload.encryptedData.size)
    val ikeMessageData = ikeMessage!!.encode()
    val ok = verifyIKEChecksum(ikeSecurityAssociation.skAr, ikeMessageData.sliceArray(0 until ikeMessageData.size - checksumLength), checksum, transformIntegrityAlgorithm!!.transformID)
    if (!ok) {
        throw Exception("Checksum failed, drop.")
    }

    // Decrypt
    val encryptedData = encryptedPayload.encryptedData.sliceArray(0 until encryptedPayload.encryptedData.size - checksumLength)
    val plainText = decryptMessage(ikeSecurityAssociation.skEr, encryptedData, transformEncryptionAlgorithm!!.transformID)
    val decryptedIKEPayload = IKEPayloadContainer()
    try {
        decryptedIKEPayload.decode(encryptedPayload.nextPayload, plainText)
    } catch (e: Exception) {
        throw Exception("Decoding decrypted payload failed")
    }
    return decryptedIKEPayload
}


fun encryptProcedure(ikeSecurityAssociation: IkeSecurityAssociation?, ikePayload: IKEPayloadContainer, responseIKEMessage: IKEMessage) {
    log.trace("EncryptProcedure")
    val transformIntegrityAlgorithm = ikeSecurityAssociation!!.integrityAlgorithm
    val transformEncryptionAlgorithm = ikeSecurityAssociation.encryptionAlgorithm
    val checksumLength = 12 // HMAC_SHA1_96

    // Encrypting
    val notificationPayloadData = try {
        ikePayload.encode()
    } catch (e: Exception) {
        throw Exception("Encoding IKE payload failed.")
    }

    log.trace("ikeSecurityAssociation.skEi [${ikeSecurityAssociation.skEi.size}] " + ikeSecurityAssociation.skEi.toUByteArrayString())
    log.trace("notificationPayloadData [${notificationPayloadData.size}] " + notificationPayloadData.toUByteArrayString())

    val encryptedData = try {
        encryptMessage(ikeSecurityAssociation.skEi, notificationPayloadData, transformEncryptionAlgorithm!!.transformID)
    } catch (e: Exception) {
        throw Exception("Error encrypting message")
    }

    log.trace("encryptedData [${encryptedData.size}] " + encryptedData.toUByteArrayString())

    val paddedEncryptedData = encryptedData + ByteArray(checksumLength)

    log.trace("encryptedData [${paddedEncryptedData.size}] " + paddedEncryptedData.toUByteArrayString())

    val sk = responseIKEMessage.payloads.buildEncrypted(ikePayload[0].type(), paddedEncryptedData)

    val responseIKEMessageData = try {
        responseIKEMessage.encode()
    } catch (e: Exception) {
        throw Exception("Encoding IKE message error")
    }

    // Calculate checksum
    val checksumOfMessage = try {
        calculateChecksum(ikeSecurityAssociation.skAi, responseIKEMessageData.copyOfRange(0, responseIKEMessageData.size - checksumLength), transformIntegrityAlgorithm!!.transformID)
    } catch (e: Exception) {
        throw Exception("Error calculating checksum")
    }
    // Adiciona checksumOfMessage ao final da encryptedData
    sk.encryptedData = sk.encryptedData.copyOfRange(0, sk.encryptedData.size - checksumLength) + checksumOfMessage
}


fun getKeyLength(transformType: UByte, transformID: UShort, attributePresent: Boolean, attributeValue: UShort): Pair<Int, Boolean> {
    return when (transformType.toInt()) {
        PayloadType.TypeEncryptionAlgorithm.value.toInt() -> when (transformID.toInt()) {
            EncryptionAlgorithm.ENCR_DES_IV64.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_DES.value.toInt() -> 8 to true
            EncryptionAlgorithm.ENCR_3DES.value.toInt() -> 24 to true
            EncryptionAlgorithm.ENCR_RC5.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_IDEA.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_CAST.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 16 to true
                    256 -> 0 to false
                    else -> 0 to false
                }
            } else 0 to false
            EncryptionAlgorithm.ENCR_BLOWFISH.value.toInt() -> if (attributePresent) {
                if (attributeValue.toInt() < 40 || attributeValue.toInt() > 448) 0 to false
                else (attributeValue.toInt() / 8) to true
            } else 0 to false
            EncryptionAlgorithm.ENCR_3IDEA.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_DES_IV32.value.toInt() -> 0 to false
            EncryptionAlgorithm.ENCR_NULL.value.toInt() -> 0 to true
            EncryptionAlgorithm.ENCR_AES_CBC.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 16 to true
                    192 -> 24 to true
                    256 -> 32 to true
                    else -> 0 to false
                }
            } else 0 to false
            EncryptionAlgorithm.ENCR_AES_CTR.value.toInt() -> if (attributePresent) {
                when (attributeValue.toInt()) {
                    128 -> 20 to true
                    192 -> 28 to true
                    256 -> 36 to true
                    else -> 0 to false
                }
            } else 0 to false
            else -> 0 to false
        }
        PayloadType.TypePseudorandomFunction.value.toInt() -> when (transformID.toInt()) {
            PRFAlgorithm.PRF_HMAC_MD5.value.toInt() -> 16 to true
            PRFAlgorithm.PRF_HMAC_SHA1.value.toInt() -> 20 to true
            PRFAlgorithm.PRF_HMAC_TIGER.value.toInt() -> 0 to false
            else -> 0 to false
        }
        PayloadType.TypeIntegrityAlgorithm.value.toInt() -> when (transformID.toInt()) {
            AuthenticationAlgorithm.AUTH_NONE.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value.toInt()-> 16 to true
            AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value.toInt() -> 20 to true
            AuthenticationAlgorithm.AUTH_DES_MAC.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_KPDK_MD5.value.toInt() -> 0 to false
            AuthenticationAlgorithm.AUTH_AES_XCBC_96.value.toInt() -> 0 to false
            else -> 0 to false
        }
        PayloadType.TypeDiffieHellmanGroup.value.toInt() -> when (transformID.toInt()) {
            DiffieHellmanGroup.DH_NONE.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_768_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_1024_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_1536_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_2048_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_3072_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_4096_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_6144_BIT_MODP.value.toInt() -> 0 to false
            DiffieHellmanGroup.DH_8192_BIT_MODP.value.toInt() -> 0 to false
            else -> 0 to false
        }
        else -> 0 to false
    }
}


fun getOutputLength(transformType: UByte, transformID: UShort, attributePresent: Boolean,
                    attributeValue: UShort): Pair<Int, Boolean> {
    when (transformType.toUInt()) {
        PayloadType.TypePseudorandomFunction.value -> {
            return when (transformID.toUInt()) {
                PRFAlgorithm.PRF_HMAC_MD5.value -> Pair(16, true)
                PRFAlgorithm.PRF_HMAC_SHA1.value -> Pair(20, true)
                PRFAlgorithm.PRF_HMAC_TIGER.value -> Pair(0, false)
                else -> Pair(0, false)
            }
        }
        PayloadType.TypeIntegrityAlgorithm.value -> {
            return when (transformID.toUInt()) {
                AuthenticationAlgorithm.AUTH_NONE.value -> Pair(0, false)
                AuthenticationAlgorithm.AUTH_HMAC_MD5_96.value -> Pair(12, true)
                AuthenticationAlgorithm.AUTH_HMAC_SHA1_96.value -> Pair(12, true)
                AuthenticationAlgorithm.AUTH_DES_MAC.value -> Pair(0, false)
                AuthenticationAlgorithm.AUTH_KPDK_MD5.value -> Pair(0, false)
                AuthenticationAlgorithm.AUTH_AES_XCBC_96.value -> Pair(0, false)
                else -> Pair(0, false)
            }
        }
        else -> return Pair(0, false)
    }
}


fun concatenateNonceAndSPI(nonce: ByteArray, spiInitiator: ULong, spiResponder: ULong): ByteArray {
    val spiBuffer = ByteBuffer.allocate(8)

    spiBuffer.putLong(spiInitiator.toLong())
    var newSlice = nonce + spiBuffer.array()

    spiBuffer.clear()
    spiBuffer.putLong(spiResponder.toLong())
    newSlice += spiBuffer.array()

    return newSlice
}


fun parseIPAddressInformationToChildSecurityAssociation(
    childSecurityAssociation: ChildSecurityAssociation?,
    trafficSelectorLocal: IndividualTrafficSelector?,
    trafficSelectorRemote: IndividualTrafficSelector?,
    ue: UeIke?,
    protocol: String
) {
    if (childSecurityAssociation == null) {
        throw Exception("childSecurityAssociation is nil")
    }
//    childSecurityAssociation.peerPublicIpAddr = IP.newIP(InetAddress.getByName(cfg.n3iwfInfo.ikeBindAddress).address)
//    childSecurityAssociation.localPublicIpAddr = IP.newIP(InetAddress.getByName(cfg.ue.localPublicIPAddr).address)
    childSecurityAssociation.peerPublicIpAddr = IP.newIP(InetAddress.getByName(ue!!.getN3iwfIp()).address)
    childSecurityAssociation.localPublicIpAddr = IP.newIP(InetAddress.getByName(ue.getUeIp()).address)

    childSecurityAssociation.trafficSelectorLocal = IPNet.newIPNet(
        IP.newIP(trafficSelectorLocal!!.startAddress),
        IPMask.newIPMask(byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))
    )
    childSecurityAssociation.trafficSelectorRemote = IPNet.newIPNet(
        IP.newIP(trafficSelectorRemote!!.startAddress),
        IPMask.newIPMask(byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))
    )

    // Select TCP traffic
    if (protocol == "tcp") {
        childSecurityAssociation.selectedIPProtocol = Proto.IPPROTO_TCP.value.toUByte()
    } else if (protocol == "gre") {
        childSecurityAssociation.selectedIPProtocol = Proto.IPPROTO_GRE.value.toUByte()
    }
}


fun parse5GQoSInfoNotify(n: Notification): PDUQoSInfo {
    val info = PDUQoSInfo()
    var offset = 0
    val data = n.notificationData
    val dataLen = data[0].toInt()
    info.pduSessionID = data[1].toUByte()
    val qfiListLen = data[2].toInt()
    offset += (3 + qfiListLen)

    if (offset > dataLen) {
        throw IllegalArgumentException("parse5GQoSInfoNotify err: Length and content of 5G-QoS-Info-Notify mismatch")
    }

    info.qfiList = data.copyOfRange(3, 3 + qfiListLen)
    info.isDefault = (data[offset] and NotifyType5G_QOS_INFOBitDCSICheck) > 0
    info.isDSCPSpecified = (data[offset] and NotifyType5G_QOS_INFOBitDSCPICheck) > 0
    return info
}


private fun appendArrays(vararg arrays: ByteArray): ByteArray {
    val totalLength = arrays.sumOf { it.size }
    val result = ByteArray(totalLength)
    var currentIndex = 0

    for (array in arrays) {
        array.copyInto(result, currentIndex)
        currentIndex += array.size
    }
    return result
}