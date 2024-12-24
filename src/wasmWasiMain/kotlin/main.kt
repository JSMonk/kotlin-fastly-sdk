@file:OptIn(kotlin.wasm.unsafe.UnsafeWasmMemoryApi::class)

import fastly.abi.BodyWriteEnds
import fastly.abi.FastlyStatuses
import fastly.abi.FastlyString
import kotlin.wasm.unsafe.withScopedMemoryAllocator

fun main() {
    val req_handle = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
    val req_body_handle = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
    val downstreamStatus = fastly.abi.fastly_http_req_body_downstream_get(req_handle, req_body_handle)

    println("Down stream status: $downstreamStatus, req_handle: ${req_handle.loadInt()}, req_body_handle: ${req_body_handle.loadInt()}")
    if (downstreamStatus != FastlyStatuses.OK) {
        return
    }

    val resp_handle_ptr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }
    val resp_body_handle_ptr = withScopedMemoryAllocator { it.allocate(Int.SIZE_BYTES) }

    val newResponseStatus = fastly.abi.fastly_http_resp_new(resp_handle_ptr)

    val resp_handle = resp_handle_ptr.loadInt()

    println("New response status: $newResponseStatus, resp_handle: $resp_handle")
    if (newResponseStatus != FastlyStatuses.OK) {
        return
    }

    val newBodyStatus = fastly.abi.fastly_http_body_new(resp_body_handle_ptr)
    val resp_body_handle = resp_body_handle_ptr.loadInt()

    println("New body status: $newBodyStatus, resp_body_handle: $resp_body_handle")
    if (newBodyStatus != FastlyStatuses.OK) {
        return
    }

    val helloWorldStr = FastlyString.fromString("Hello, world!")
    val writtenPtr = withScopedMemoryAllocator { it.allocate(Long.SIZE_BYTES) }

    var pos = 0
    while (pos < helloWorldStr.len) {
        val writeStatus = fastly.abi.fastly_http_body_write(
            resp_body_handle,
            helloWorldStr.pointer + pos,
            (helloWorldStr.len - pos).toUInt(),
            BodyWriteEnds.BACK,
            writtenPtr
        )

        println("Write status on position $pos: $writeStatus, written: ${writtenPtr.loadInt()}")
        if (writeStatus != FastlyStatuses.OK) {
            return
        }

        pos += writtenPtr.loadInt()
    }

    val finishStatus = fastly.abi.fastly_http_resp_send_downstream(
        resp_handle,
        resp_body_handle,
        0u
    )

    println("Finish status: $finishStatus")
    if (finishStatus != FastlyStatuses.OK) {
        return
    }
}
