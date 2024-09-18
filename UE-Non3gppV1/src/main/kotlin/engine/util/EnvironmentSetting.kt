package engine.util

import org.slf4j.LoggerFactory

class EnvironmentSetting {
    private val log = LoggerFactory.getLogger(EnvironmentSetting::class.java)


    private fun executeCommand(command1: String) {
        val command = "sudo $command1"
        log.trace("Comando executado no shell: $command")
        val process = Runtime.getRuntime().exec(arrayOf("bash", "-c", command))
        process.waitFor()
        val exitCode = process.exitValue()
        if (exitCode != 0) {
            throw RuntimeException("$command failed!")
        } else {
            log.trace("$command executed successfully!")
        }
    }


    fun xfrmPolicyFlush() {
        val xfrmPolicyFlushCommand = "ip xfrm policy flush"
        executeCommand(xfrmPolicyFlushCommand)
    }

    fun xfrmStateFlush() {
        val xfrmStateFlushCommand = "ip xfrm state flush"
        executeCommand(xfrmStateFlushCommand)
    }


    fun linkAddXfrm(ipsecInterfaceName: String, linkInterface: String, ifId: Int, mtu: Int) {
        var command = "ip link add dev $ipsecInterfaceName type xfrm dev $linkInterface if_id 0x${ifId}"
        executeCommand(command)
        command = "ip link set dev $ipsecInterfaceName mtu $mtu"
        executeCommand(command)
    }

    fun addrAdd(linkInterfaceName: String, addr: String) {
        val command1 = "ip addr add $addr dev $linkInterfaceName"
        executeCommand(command1)
    }

    fun linkSetUp(linkInterfaceName: String) {
        val command1 = "ip link set $linkInterfaceName up"
        executeCommand(command1)
    }


    fun linkAddGRE(linkGRE: String, linkInterface: String, ipLocal: String, ipRemoto: String, ikey: Long, okey: Long) {
        var command = "ip link add dev $linkGRE type gre dev $linkInterface remote $ipRemoto local $ipLocal ikey $ikey okey $okey"
        executeCommand(command)

        command = "ip link set $linkGRE mtu 1420"   // ANDROID = 1300
        executeCommand(command)
    }


    fun routeAddDefault(linkGRE: String) {
        val command = "ip route add default dev $linkGRE"
        executeCommand(command)
    }


    fun routeAdd(ipsecInterfaceName: String, ipRouteAdd:String, ipLocal: String) {
        val command = "ip route add $ipRouteAdd dev $ipsecInterfaceName proto kernel scope link src $ipLocal"
        executeCommand(command)
    }


    fun linkDel(interfaceName: String) {
        val command = "ip link delete $interfaceName"
        executeCommand(command)
    }

    fun routeDel(ipsecInterfaceName: String, ipRouteAdd:String) {
        val command = "ip route del $ipRouteAdd dev $ipsecInterfaceName"
        executeCommand(command)
    }

    fun routeDelDefault() {
        val command = "ip route del default"
        executeCommand(command)
    }
}