package internal.ipsec

import config.Config
import go.net.IPNet
import go.net.TCPAddr
import internal.ike.context.ChildSecurityAssociation
import internal.ike.context.UeIke
import internal.ipsec.context.UeIpSec
import internal.ipsec.dispatch.dispatch
import internal.xfrm.applyXFRMRule
import internal.xfrm.setupIpsecXfrmi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import pkg.metrics.UeMetrics
import pkg.utils.Utils
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Duration
import java.time.Instant

class Ipsec {
    fun run(
        cfg: Config,
        ueInnerAddr: IPNet,
        childSecurityAssociation: ChildSecurityAssociation,
        n3iwfNasAddr: TCPAddr,
        ueIke: UeIke
    ) {
        // Obter interface por nome
        val interfaceName = try {
            Utils().getInterfaceName(cfg.ue.localPublicIPAddr)
        } catch (e: Exception) {
            throw RuntimeException("[UE][IPSEC] Error in get UE interface name: ${e.message}", e)
        }

        // Configurar IPsec Xfrmi
        val newXfrmiName = "${cfg.ue.ipsecInterface.name}-default"
        val linkIPSec = try {
            setupIpsecXfrmi(cfg, interfaceName, cfg.ue.ipsecInterface.mark.toUInt(), ueInnerAddr)
        } catch (e: Exception) {
            throw RuntimeException("[UE][IPSEC] Error in setup IPSEC interface: ${e.message}", e)
        }

        ueIke.nasContext!!.setXfrmInterface(linkIPSec)

        // Aplicar regras XFRM
        try {
            applyXFRMRule(
                true,
                cfg.ue.ipsecInterface.mark.toUInt(),
                childSecurityAssociation
            )
        } catch (e: Exception) {
            throw RuntimeException("[UE][IPSEC] Error in setup XFRM rules: ${e.message}", e)
        }

        // Endereço TCP do UE - Convertendo IP para InetAddress
        val localInetAddress = InetAddress.getByAddress(ueInnerAddr.ip.ipBytes)

        // Endereço TCP do N3IWF NAS - Convertendo IP para InetAddress
        val n3iwfInetAddress = InetAddress.getByAddress(n3iwfNasAddr.IP.ipBytes)
        val n3iwfSocketAddress = InetSocketAddress(n3iwfInetAddress, n3iwfNasAddr.port)

        // Criando o socket e conectando ao endereço NAS do N3IWF
        val tcpConnWithN3iwf = try {
            Socket().apply {
                bind(InetSocketAddress(localInetAddress, 0)) // Bind ao endereço local com porta dinâmica
                connect(n3iwfSocketAddress) // Conecta ao endereço N3IWF NAS
            }
        } catch (e: Exception) {
            throw RuntimeException("[UE][IPSEC][CP] Error in setup dial TCP: ${e.message}", e)
        }

        // Criar contexto de UE para IPsec
        val ueIpSec = UeIpSec.newUeIpSec(
            ueIke.nasContext!!,
            tcpConnWithN3iwf,
            newXfrmiName
        )

        ueIke.nasContext!!.setIpsecTcp(tcpConnWithN3iwf)

        println("[UE][IPSEC] IPSEC SA Tunnel established")
        ueIke.ipsecTime = Duration.between(ueIke.beginTime, Instant.now())
        UeMetrics().addIpsecTime(ueIke.ipsecTime.toMillis())

        // Lidar com servidor TCP/NAS
        GlobalScope.launch {
            listenAndServe(ueIpSec)
        }
    }


    private fun listenAndServe(ue: UeIpSec) {
        val listener = ue.getTcpConn()
        val data = ByteArray(65535)

        while (true) {
            try {
                val n = listener!!.inputStream.read(data)
                if (n == -1) {
                    println("[UE][IPSEC][TCP] Read from TCP failed")
                    continue
                }

                val forwardData = data.copyOfRange(0, n)

                // Lidar com a mensagem no handler IPSEC de forma concorrente usando corrotinas
                GlobalScope.launch {
                    dispatch(ue, forwardData)
                }

            } catch (e: Exception) {
                println("[UE][IPSEC][TCP] Read from TCP failed: ${e.message}")
                continue
            }
        }
    }
}