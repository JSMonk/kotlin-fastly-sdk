@file:OptIn(kotlin.wasm.unsafe.UnsafeWasmMemoryApi::class)

import fastly.http.downstream


fun main() {
    val (_, resp) = downstream()
    resp.body.writeAll("Hello, world!")
    resp.finish()
}
