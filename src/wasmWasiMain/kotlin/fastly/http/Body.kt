@file:OptIn(kotlin.wasm.unsafe.UnsafeWasmMemoryApi::class)
package fastly.http

import fastly.abi.BodyWriteEnds
import fastly.abi.FastlyString
import kotlin.wasm.unsafe.withScopedMemoryAllocator

class Body internal constructor(
    internal val handle: Int
) {
    fun writeAll(string: String) {
        val writtenPtr = withScopedMemoryAllocator { it.allocate(Long.SIZE_BYTES) }
        val (stringPtr, stringLength) = FastlyString.fromString(string)

        var pos = 0
        while (pos < stringLength) {
            fastly.abi.fastly_http_body_write(
                handle,
                stringPtr + pos,
                (stringLength - pos).toUInt(),
                BodyWriteEnds.BACK,
                writtenPtr
            )

            pos += writtenPtr.loadInt()
        }
    }
}