@file:OptIn(kotlin.wasm.unsafe.UnsafeWasmMemoryApi::class)
package fastly.http

import kotlin.wasm.unsafe.withScopedMemoryAllocator

class Request private constructor(
    private val handle: Int,
    private val body: Body
) {
    companion object {
        fun downstream(): Request {
            val reqHandlePtr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
            val reqBodyHandlePtr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
            fastly.abi.fastly_http_req_body_downstream_get(reqHandlePtr, reqBodyHandlePtr)
            return Request(reqHandlePtr.loadInt(), Body(reqBodyHandlePtr.loadInt()))
        }
    }
}