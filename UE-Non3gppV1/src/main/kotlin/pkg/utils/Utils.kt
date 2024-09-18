package pkg.utils

import engine.util.Quintuple
import java.net.InetAddress
import java.net.NetworkInterface

class Utils {

    fun getInterfaceName(ipAddress: String): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces().toList()
            val resolvedAddress = InetAddress.getByName(ipAddress)
            val resolvedIp = resolvedAddress.hostAddress

            for (inter in interfaces) {
                val addrs = inter.interfaceAddresses

                for (addr in addrs) {
                    val addrIp = addr.address.hostAddress
                    if (resolvedIp == addrIp) {
                        return inter.name
                    }
                }
            }
        } catch (e: Exception) {
            throw Exception("Error in getInterfaceName '$ipAddress': ${e.message}")
        }
        throw Exception("Cannot find interface name")
    }


    private fun reverseStr(s: String): String {
        // reverse string
        val aux = StringBuilder()
        for (valor in s) {
            aux.insert(0, valor)
        }
        return aux.toString()
    }


    fun getMccAndMncInOctets(mcc: String, mnc: String): ByteArray {
        // reverse mcc and mnc
        val reversedMcc = reverseStr(mcc)
        val reversedMnc = reverseStr(mnc)

        // include mcc and mnc in octets
        val oct5 = reversedMcc.substring(1, 3)
        val oct6: String
        val oct7: String

        if (reversedMnc.length == 2) {
            oct6 = "f" + reversedMcc[0]
            oct7 = reversedMnc
        } else {
            oct6 = reversedMnc[0].toString() + reversedMcc[0]
            oct7 = reversedMnc.substring(1, 3)
        }

        // convert to bytes
        val resultHex = oct5 + oct6 + oct7
        val resu = resultHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return resu
    }


    fun parseUint8ToHexadecimal(num: UByte): String {
        return num.toString(16) // Converte o número para uma string hexadecimal
    }


    fun parseStringToHexadecimal(num: String): String {
        return num.toByteArray().joinToString("") { "%02x".format(it) } // Converte cada byte da string em hexadecimal
    }


    fun validateLenStringField(label: String, value: String, size: UByte): String? {
        return when {
            value.isEmpty() -> "$label cannot be empty"
            value.length != size.toInt() -> "$label must have ${size.toInt()} characters"
            else -> null // Retorna null se não houver erro
        }
    }


    fun convertToHexByte(str: String): Byte {
        return try {
            if (str.all { it.isDigit() }) {
                str.toInt(10).toByte() // Converte a string numérica para base 10
            } else {
                str.toInt(16).toByte() // Converte a string hexadecimal para base 16
            }
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("Invalid input string: $str", e)
        }
    }


    fun encodeUeSuci(msin: String): Quintuple<Byte, Byte, Byte, Byte, Byte> {
        // reverse imsi string
        val aux = msin.reversed()

        // calculate decimal value
        val suci = try {
            aux.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (e: Exception) {
            return Quintuple(0, 0, 0, 0, 0)
        }

        // return decimal value
        return if (msin.length == 8) {
            Quintuple(suci[0], suci[1], suci[2], suci[3], 0)
        } else {
            Quintuple(suci[0], suci[1], suci[2], suci[3], suci[4])
        }
    }
}



