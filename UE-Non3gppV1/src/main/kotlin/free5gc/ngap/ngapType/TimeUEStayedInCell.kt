package free5gc.ngap.ngapType

data class TimeUEStayedInCell(
    val value: Long
) {
    init {
        require(value in 0..4095) { "Value must be in the range 0..4095" }
    }
}