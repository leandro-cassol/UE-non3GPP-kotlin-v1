package internal.ike

import config.Config
import engine.util.toUByteArrayString
import internal.ike.context.UeIke
import internal.ike.dispatch.dispatch
import internal.ike.trigger.initRegistration
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

class ControlPlane {

    private val log = LoggerFactory.getLogger(ControlPlane::class.java)


    fun run(cfg: Config, ue: UeIke) {
        // N3WIF UDP address
        val n3iwfUdp = InetSocketAddress(cfg.n3iwfInfo.ikeBindAddress, cfg.n3iwfInfo.ikeBindPort.toInt())

        // UE UDP address
        val ueUdp = InetSocketAddress(cfg.ue.localPublicIPAddr, cfg.ue.localPublicPortUDPConnection.toInt())

        // Connect to N3WIF/UE UDP
        val connUdp = DatagramSocket(ueUdp).apply {
            connect(n3iwfUdp)
        }

        // udp connection of UE
        ue.setN3iwfIp(cfg.n3iwfInfo.ikeBindAddress)
        ue.setUEIp(cfg.ue.localPublicIPAddr)
        ue.setUdpConn(connUdp)
        ue.n3iwfUdp = n3iwfUdp

        // handle messages in udp socket
        GlobalScope.launch {
            listenAndServe(cfg, ue)
        }

        // init the registration of UE
        initRegistration(ue)
    }


    private fun listenAndServe(cfg: Config, ue: UeIke) {
        val listener = ue.getUdpConn()
        val buffer = ByteArray(65535)

        while (true) {
            val packet = DatagramPacket(buffer, buffer.size)
            listener!!.receive(packet)

            val data = packet.data.copyOf(packet.length)
            log.trace("[IKE][SERVICE][LISTEN] [${data.size}] = ${data.toUByteArrayString()}")

            // handle the message in ike handler
            GlobalScope.launch {
                dispatch(cfg, ue, data)
            }
        }
    }
}