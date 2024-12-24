@file:OptIn(kotlin.wasm.unsafe.UnsafeWasmMemoryApi::class)
package fastly.http

import kotlin.wasm.unsafe.withScopedMemoryAllocator

class Response private constructor(
    private val handle: Int,
    val body: Body
) {
    fun finish() {
        fastly.abi.fastly_http_resp_send_downstream(
            handle,
            body.handle,
            0u
        )
    }

    companion object {
        fun downstream(): Response {
            val resHandlePtr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
            val resBodyHandlePtr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }

            val resHandle = fastly.abi.fastly_http_resp_new(resHandlePtr).let { resHandlePtr.loadInt() }
            val resBodyHandle = fastly.abi.fastly_http_body_new(resBodyHandlePtr).let { resBodyHandlePtr.loadInt() }

            return Response(resHandle, Body(resBodyHandle))
        }
    }
}
