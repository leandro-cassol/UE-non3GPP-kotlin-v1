package cmd

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.LoggerContext
import config.Config
import org.slf4j.LoggerFactory
import pkg.metrics.UeMetrics
import pkg.template.ueNon3GPPConnection


private const val VERSION = "1.0.0"



class CLICommand(
    val name: String,
    val aliases: List<String> = listOf(),
    val usage: String,
    val action: () -> Unit
)


class CLIApplication {
    private val commands = mutableListOf<CLICommand>()

    fun addCommand(command: CLICommand) {
        commands.add(command)
    }

    fun run(args: Array<String>) {
        if (args.isEmpty()) {
            printHelp()
            return
        }

        val commandName = args[0]
        val command = commands.find { it.name == commandName || it.aliases.contains(commandName) }

        if (command == null) {
            println("Command not found: $commandName")
            printHelp()
            return
        }
        try {
            command.action()
        } catch (e: Exception) {
            println("Error executing command: ${e.message}")
        }
    }

    private fun printHelp() {
        println("Available commands:")
        commands.forEach {
            println("- ${it.name} (${it.aliases.joinToString(", ")}) : ${it.usage}")
        }
    }
}


private fun init(config: Config) {
    setGlobalLogLevel("INFO")

    var log = LoggerFactory.getLogger("Main")
    log.info("UE-non3GPP version $VERSION")

    if (config.logs.level == "trace") {
        setGlobalLogLevel("TRACE")
    } else {
        setGlobalLogLevel("INFO")
    }
    log = LoggerFactory.getLogger("Main")

    log.info("Log - INFO")
    log.trace("Log - TRACE")
}


private fun setGlobalLogLevel(level: String) {
    val loggerContext = LoggerFactory.getILoggerFactory() as LoggerContext
    val log = loggerContext.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)
    log.level = Level.toLevel(level, Level.INFO) // Default to INFO if level string is invalid
}


fun main(args: Array<String>) {
    val cfg = Config.getConfig()
    init(cfg)
    UeMetrics().initMetricsFile()
    val log = LoggerFactory.getLogger("Main")

    val app = CLIApplication()

    app.addCommand(
        CLICommand(
            name = "ue",
            aliases = listOf("non3GPPAccess"),
            usage = "Non-3GPP UE-Connection"
        ) {
            val name = "Non 3GPP UE attached with configuration"
            log.info("---------------------------------------")
            log.info("[UE] Starting connect function: $name")
            log.info("[UE] Info MSIN: ${cfg.ue.msin}")

            UeMetrics().removeMetricsFile()
            ueNon3GPPConnection(cfg)
        }
    )

    try {
        app.run(args)
    } catch (e: Exception) {
        log.error(e.message ?: "Unknown error")
    }
}
