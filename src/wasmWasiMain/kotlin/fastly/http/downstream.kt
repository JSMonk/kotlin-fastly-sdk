package fastly.http

data class Downstream(
    val request: Request,
    val response: Response
)

fun downstream() = Downstream(Request.downstream(), Response.downstream())