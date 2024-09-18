package internal.ike.dispatch

import config.Config
import internal.ike.context.UeIke
import internal.ike.handler.handleCreateChildSa
import internal.ike.handler.handleIKEAUTH
import internal.ike.handler.handleIkeSaInit
import internal.ike.message.ExchangeType
import internal.ike.message.IKEMessage

fun dispatch(cfg: Config, ue: UeIke, msg: ByteArray) {
    // Decodifica a mensagem IKE
    val ikeMessage = IKEMessage()
    ikeMessage.decode(msg)

    // Processa a mensagem de acordo com o ExchangeType
    when (ikeMessage.exchangeType) {
        ExchangeType.IKE_SA_INIT.value.toUByte() -> {
            handleIkeSaInit(ue, ikeMessage)
        }
        ExchangeType.IKE_AUTH.value.toUByte() -> {
            handleIKEAUTH(cfg, ue, ikeMessage)
        }
        ExchangeType.CREATE_CHILD_SA.value.toUByte() -> {
            handleCreateChildSa(cfg, ue, ikeMessage)
        }
        else -> {
            throw Exception("Unimplemented IKE message type, exchange type: ${ikeMessage.exchangeType}")
        }
    }
}
