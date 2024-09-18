package internal.gre

import config.Config
import engine.util.EnvironmentSetting
import go.net.IP
import go.net.IPMask
import go.net.IPNet
import internal.ike.context.ChildSecurityAssociation
import internal.ike.context.PDUQoSInfo
import internal.ike.context.UeIke
import internal.xfrm.applyXFRMRule
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch


class Gre {

    companion object {
        fun run(
            cfg: Config,
            ueIpAddr: IPNet, n3iwfIpUp: IP, childSecurityAssociation: ChildSecurityAssociation,
            ueIke: UeIke, qosInfo: PDUQoSInfo?
        ) {
            // Simulate Apply XFRM rule
            try {
                applyXFRMRule(false, cfg.ue.ipsecInterface.mark.toUInt(), childSecurityAssociation)
            } catch (e: Exception) {
                throw Exception("Error occurs when Apply XFRM Rule: $e")
            }

            val newGREName = "${cfg.ue.greInterface.name}${cfg.ue.pduSessionId}"
            val parentIfaceName = "${cfg.ue.ipsecInterface.name}-default"

            // Wait for PDU session active
            // handle messages in udp socket
            GlobalScope.launch {
                while (ueIke.nasContext!!.stateSM != 2) {
                    delay(1000)
                }
                configureGreInterface(ueIpAddr, n3iwfIpUp, ueIke, qosInfo, newGREName, parentIfaceName)
            }
        }


        private fun configureGreInterface(
            ueIpAddr: IPNet, n3iwfIpUp: IP, ueIke: UeIke, qosInfo: PDUQoSInfo?, newGREName: String, parentIfaceName: String
        ) {
            val linkGRE: String?
            try {
                linkGRE = setupGreTunnel(
                    newGREName,
                    parentIfaceName,
                    ueIpAddr.ip,
                    n3iwfIpUp,
                    ueIke.nasContext!!.pduSession.pduAddress,
                    qosInfo
                )
            } catch (e: Exception) {
                throw Exception("Error occurs when Setup GRE Tunnel: $e")
            }

            ueIke.nasContext!!.setGREInterface(linkGRE)

            val ipRouteAdd = "10.0.0.0/24"
            ueIke.nasContext!!.setGRERoute(ipRouteAdd)

            EnvironmentSetting().routeAddDefault(linkGRE)
        }


        private fun setupGreTunnel(
            greIfaceName: String, parentIfaceName: String, ueTunnelAddr: IP,
            n3iwfTunnelAddr: IP, pduIp: IP, qosInfo: PDUQoSInfo?
        ): String {
            var greKeyField = 0u

            qosInfo?.let {
                greKeyField = ((it.qfiList[0].toUInt() and 0x3FU) shl 24)
            }

            EnvironmentSetting().linkAddGRE(greIfaceName, parentIfaceName, ueTunnelAddr.string(), n3iwfTunnelAddr.string(), greKeyField.toLong(), greKeyField.toLong())

            val pduAddr = IPNet()
            pduAddr.ip = pduIp
            pduAddr.mask = IPMask.newIPMask(byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()))

            EnvironmentSetting().addrAdd(greIfaceName, pduAddr.string())

            EnvironmentSetting().linkSetUp(greIfaceName)

            return greIfaceName
        }
    }
}