package pkg.template

import config.Config
import internal.ike.ControlPlane
import internal.ike.context.UeIke
import internal.nas.context.ArgumentsNas
import internal.nas.context.UeNas
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

private val log = LoggerFactory.getLogger("Ue-registration")

fun ueNon3GPPConnection(cfg: Config) {
    // Criação dos argumentos para a instância Nas
    val argsNas = ArgumentsNas().apply {
        mcc = cfg.ue.hplmn.mcc
        mnc = cfg.ue.hplmn.mnc
        msin = cfg.ue.msin
        ranUeNgapId = cfg.ue.ranUeNgapId
        k = cfg.ue.authSubscription.permanentKeyValue
        opc = cfg.ue.authSubscription.opcValue
        op = cfg.ue.authSubscription.opValue
        amf = cfg.ue.authenticationManagementField
        sqn = cfg.ue.authSubscription.sequenceNumber
        sst = cfg.ue.snssai.sst
        sd = cfg.ue.snssai.sd
        dnn = cfg.ue.dnnString
    }

    val ueNas = UeNas.newUeNas(argsNas)
    log.info("[UE][NAS] NAS Context Created")

    val ueIke = UeIke.newUeIke(ueNas)
    log.info("[UE][IKE] IKE Context Created")

    // Inicialização do plano de controle UE
    ControlPlane().run(cfg, ueIke)
    log.info("[UE][IKE] Control Plane Created")

    // Usando Signals para tratar interrupção
    val sigUE = SignalHandler()
    sigUE.handleInterrupt {
        try {
            ueIke.terminate()
        } catch (e: Exception) {
            println("[UE][IKE] IKE Context Termination failed")
            return@handleInterrupt
        }

        try {
            ueNas.terminate()
        } catch (e: Exception) {
            println("[UE][NAS] NAS Context Termination failed")
            return@handleInterrupt
        }

        println("[UE] UE terminated")
        exitProcess(0)
    }
}

// Classe auxiliar para tratar interrupções
class SignalHandler {
    fun handleInterrupt(onInterrupt: () -> Unit) {
        val shutdownHook = Thread {
            println("Interrupt signal received, terminating...")
            onInterrupt()
        }
        Runtime.getRuntime().addShutdownHook(shutdownHook)

        // Espera indefinidamente até receber sinal de interrupção
        while (true) {
            TimeUnit.SECONDS.sleep(1)
        }
    }
}

class UeHandler(
    val nasInfo: UeNas?,
    val ikeInfo: UeIke?
)
