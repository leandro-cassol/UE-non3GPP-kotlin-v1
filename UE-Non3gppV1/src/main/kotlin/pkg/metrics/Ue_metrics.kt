package pkg.metrics

import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException
import java.nio.file.Paths
import kotlin.system.exitProcess


private val log = LoggerFactory.getLogger("UeMetrics")


var ueMetrics: String = "ue-metrics.txt"


class UeMetrics {

    companion object {
        fun newInstance(): UeMetrics {
            return UeMetrics()
        }
    }

    private fun getMetricsFilePath(): String {
        val dir = rootDir()
        return "$dir/UE-Non3gppV1/src/main/kotlin/pkg/metrics/$ueMetrics"
    }

    fun initMetricsFile() {
        val filename = getMetricsFilePath()
        val file = File(filename)
        if (!file.exists()) {
            createMetricsFile()
        }
    }

    fun removeMetricsFile() {
        val filename = getMetricsFilePath()
        val file = File(filename)
        log.trace("[UE] [Metrics] Remove Ue Metrics File: $filename")
        if (file.exists()) {
            if (file.delete()) {
                log.trace("[UE] [Metrics] Metrics file removed: $filename")
            } else {
                println("[UE] [Metrics] could not remove metrics file in: $filename")
                exitProcess(1)
            }
        }
    }

    private fun createMetricsFile() {
        val filename = getMetricsFilePath()
        val initialContent = "Este é o conteúdo inicial do arquivo."
        try {
            File(filename).bufferedWriter().use { out ->
                out.write(initialContent)
            }
            println("[UE][Metrics] Metrics File was created: $filename")
        } catch (e: IOException) {
            println("[UE] [Metrics] could not open metrics file: $e")
            exitProcess(1)
        }
    }

    private fun rootDir(): String {
        val path = Paths.get("").toAbsolutePath().toString()
        return File(path).parent
    }

    fun addRegisterTime(duration: Long) {
        val newText = "RegisterTime:${duration}ms"
        addNewLine(newText)
    }

    fun addPduTime(duration: Long) {
        val newText = "PDUTime:${duration}ms"
        addNewLine(newText)
    }

    fun addIpsecTime(duration: Long) {
        val newText = "IpsecTime:${duration}ms"
        addNewLine(newText)
    }

    fun addSecurityTime(duration: Long) {
        val newText = "SecurityTime:${duration}ms"
        addNewLine(newText)
    }

    fun addAuthTime(duration: Long) {
        val newText = "AuthTime:${duration}ms"
        addNewLine(newText)
    }

    fun getMetricsValue(key: String): String {
        val filename = getMetricsFilePath()

        val file = File(filename)
        if (!file.exists()) {
            throw IOException("[UE] [Metrics] could not open metrics file")
        }

        file.bufferedReader().useLines { lines ->
            lines.forEach { line ->
                val partes = line.split(":", limit = 2)
                if (partes.size != 2) {
                    log.info("[UE] [Metrics] invalid format line metrics file")
                }
                else {
                    val propriedade = partes[0].trim()
                    val valor = partes[1].trim()

                    if (propriedade == key) {
                        return valor
                    }
                }
            }
        }
        throw NoSuchElementException("[UE] [Metrics] property not found into metrics file")
    }

    private fun addNewLine(newLine: String) {
        val filename = getMetricsFilePath()
        try {
            File(filename).appendText("$newLine\n")
        } catch (e: IOException) {
            println("[UE] [Metrics] could not write new line into metrics file: $e")
            //exitProcess(1)
        }
    }
}