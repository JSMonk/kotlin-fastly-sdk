@file:OptIn(UnsafeWasmMemoryApi::class, ExperimentalUnsignedTypes::class)
@file:Suppress("WASM_IMPORT_EXPORT_UNSUPPORTED_PARAMETER_TYPE")

// TODO: Setup auto-generating of this API via witx-codegen from https://github.com/fastly/Viceroy/tree/main/lib/compute-at-edge-abi
// Adapted from https://github.com/jedisct1/zigly

package fastly.abi

import kotlin.UInt
import kotlin.text.iterator
import kotlin.wasm.unsafe.Pointer
import kotlin.wasm.unsafe.UnsafeWasmMemoryApi
import kotlin.wasm.unsafe.withScopedMemoryAllocator

typealias WasiHandle = Int
typealias Char8 = Byte
typealias Char32 = UInt

typealias WasiPtr<T> = Pointer
typealias WasiMutPtr<T> = Pointer

data class FastlyBuffer(val pointer: WasiPtr<UByte>, val len: Int) {
    fun toByteArray() = ByteArray(len) { (pointer + it).loadByte() }

    companion object {
        fun fromByteArray(buffer: ByteArray): FastlyBuffer {
            val ptr = withScopedMemoryAllocator {
                val rawPointer = it.allocate(buffer.size * UByte.SIZE_BYTES)
                var current = rawPointer
                for (it in buffer) {
                    current.storeByte(it)
                    current += 1
                }
                rawPointer
            }

            return FastlyBuffer(ptr, buffer.size)
        }
    }
}

data class FastlyString(val pointer: WasiPtr<Char8>, val len: Int) {
    override fun toString(): String {
        return buildString {
            var current = pointer
            repeat(len) {
                append(current.loadByte().toInt().toChar())
                current += Char8.SIZE_BYTES
            }
        }
    }

    companion object {
        fun fromString(str: String): FastlyString {
            val ptr = withScopedMemoryAllocator {
                val rawPointer = it.allocate(str.length * Char8.SIZE_BYTES)
                var current = rawPointer
                for (c in str) {
                  current.storeByte(c.code.toByte())
                  current += 1
                }
                rawPointer
            }

            return FastlyString(ptr, str.length)
        }
    }
}

private class StructReader(private var ptr: Pointer) {
    fun readString(): String {
        val ptr = Pointer(this.ptr.loadInt().toUInt())
        this.ptr += Int.SIZE_BYTES
        val len = this.ptr.loadInt()
        this.ptr += Int.SIZE_BYTES
        return FastlyString(ptr, len).toString()
    }

    fun readUInt(): UInt {
        val value = this.ptr.loadInt().toUInt()
        this.ptr += Int.SIZE_BYTES
        return value
    }

    fun readUByte(): UInt {
        val value = this.ptr.loadInt().toUInt()
        this.ptr += Int.SIZE_BYTES
        return value
    }

    fun readInt(): Int {
        val value = this.ptr.loadInt()
        this.ptr += Int.SIZE_BYTES
        return value
    }

    fun readPointer(): Pointer {
        val value = Pointer(this.ptr.loadInt().toUInt())
        this.ptr += Int.SIZE_BYTES
        return value
    }
}

private class StructWriter(private var ptr: Pointer) {
    fun writeString(value: String) {
        val (ptr, len) = FastlyString.fromString(value)
        this.ptr.storeInt(ptr.address.toInt())
        this.ptr += Int.SIZE_BYTES
        this.ptr.storeInt(len)
        this.ptr += Int.SIZE_BYTES
    }

    fun writeULong(value: ULong) {
        this.ptr.storeLong(value.toLong())
        this.ptr += Long.SIZE_BYTES
    }

    fun writeUInt(value: UInt) {
        this.ptr.storeInt(value.toInt())
        this.ptr += Int.SIZE_BYTES
    }

    fun writeUShort(value: UShort) {
        this.ptr.storeShort(value.toShort())
        this.ptr += Int.SIZE_BYTES
    }

    fun writeUByte(value: UByte) {
        this.ptr.storeByte(value.toByte())
        this.ptr += Int.SIZE_BYTES
    }

    fun writeInt(value: Int) {
        this.ptr.storeInt(value)
        this.ptr += Int.SIZE_BYTES
    }

    fun writePointer(pointer: Pointer) {
        this.ptr.storeInt(pointer.address.toInt())
        this.ptr += Int.SIZE_BYTES
    }

    fun writeBytes(bytes: ByteArray) {
        val (ptr, len) = FastlyBuffer.fromByteArray(bytes)
        this.ptr.storeInt(ptr.address.toInt())
        this.ptr += Int.SIZE_BYTES
        this.ptr.storeInt(len)
        this.ptr += Int.SIZE_BYTES

    }
}


/**
 * Status codes returned from hostcalls.
 **/
typealias FastlyStatus = UInt
object FastlyStatuses {
    const val OK = 0u
    const val ERROR = 1u
    const val INVAL = 2u
    const val BADF = 3u
    const val BUFLEN = 4u
    const val UNSUPPORTED = 5u
    const val BADALIGN = 6u
    const val HTTPINVALID = 7u
    const val HTTPUSER = 8u
    const val HTTPINCOMPLETE = 9u
    const val NONE = 10u
    const val HTTPHEADTOOLARGE = 11u
    const val HTTPINVALIDSTATUS = 12u
    const val LIMITEXCEEDED = 13u
    const val AGAIN = 14u
}

/**
 * A tag indicating HTTP protocol versions.
 **/
typealias HttpVersion = UInt
object HttpVersions {
    const val HTTP_09 = 0u
    const val HTTP_10 = 1u
    const val HTTP_11 = 2u
    const val H_2 = 3u
    const val H_3 = 4u
}

/**
 * HTTP status codes.
 **/
typealias HttpStatus = UShort;

typealias BodyWriteEnd = UInt
object BodyWriteEnds {
    const val BACK = 0u
    const val FRONT = 1u
}

/**
 * A handle to an HTTP request or response body.
 */
typealias BodyHandle = WasiHandle

/**
 * A handle to an HTTP request.
 */
typealias RequestHandle = WasiHandle

/**
 * A handle to an HTTP response.
 */
typealias ResponseHandle = WasiHandle

/**
 * A handle to a currently-pending asynchronous HTTP request.
 */
typealias PendingRequestHandle = WasiHandle

/**
 * A handle to a logging endpoint.
 */
typealias EndpointHandle = WasiHandle

/**
 * A handle to an Edge Dictionary.
 */
typealias DictionaryHandle = WasiHandle

/**
 * A handle to an Object Store.
 */
typealias ObjectStoreHandle = WasiHandle

/**
 * A handle to a pending Object Store lookup.
 */
typealias PendingObjectStoreLookupHandle = WasiHandle

/**
 * A handle to a pending Object Store insert.
 */
typealias PendingObjectStoreInsertHandle = WasiHandle

/**
 * A handle to a pending Object Store delete.
 */
typealias PendingObjectStoreDeleteHandle = WasiHandle

/**
 * A handle to a Secret Store.
 */
typealias SecretStoreHandle = WasiHandle

/**
 * A handle to an individual secret.
 */
typealias SecretHandle = WasiHandle

/**
 * A handle to an object supporting generic async operations.
 * Can be either a `BodyHandle` or a `PendingRequestHandle`.
 *
 * Each async item has an associated I/O action:
 *
 * * Pending requests: awaiting the response headers / `Response` object
 * * Normal bodies: reading bytes from the body
 * * Streaming bodies: writing bytes to the body
 *
 * For writing bytes, note that there is a large host-side buffer that bytes
 * can eagerly be written into, even before the origin itself consumes that data.
 */
typealias AsyncItemHandle = WasiHandle

/**
 * A "multi-value" cursor.
 */
typealias MultiValueCursor = UInt

/**
 * -1 represents "finished", non-negative represents a multi-value cursor.
 */
typealias MultiValueCursorResult = Long

/**
 * An override for response caching behavior.
 * A zero value indicates that the origin response's cache control headers should be used.
 */
typealias CacheOverrideTag = UInt

const val CACHE_OVERRIDE_TAG_PASS = 0x1u
const val CACHE_OVERRIDE_TAG_TTL = 0x2u
const val CACHE_OVERRIDE_TAG_STALE_WHILE_REVALIDATE = 0x4u
const val CACHE_OVERRIDE_TAG_PCI = 0x8u

typealias NumBytes = ULong

typealias HeaderCount = UInt

typealias IsDone = UInt

typealias DoneIdx = UInt

typealias IsValid = UInt

typealias Inserted = UInt

typealias ReadyIdx = UInt

typealias Port = UShort

typealias TimeoutMs = UInt

typealias BackendExists = UInt

typealias IsDynamic = UInt

typealias IsSsl = UInt

typealias BackendHealth = UInt

object BackendHealths {
    const val UNKNOWN = 0u
    const val HEALTHY = 1u
    const val UNHEALTHY = 2u
}

typealias ContentEncodings = UInt

object ContentEncodingsValues {
    const val GZIP = 1u
}

typealias FramingHeadersMode = UInt

object FramingHeadersModes {
    const val AUTOMATIC = 0u
    const val MANUALLY_FROM_HEADERS = 1u
}

typealias HttpKeepaliveMode = UInt

object HttpKeepaliveModes {
    const val AUTOMATIC = 0u
    const val NO_KEEPALIVE = 1u
}

typealias TlsVersion = UInt
object TlsVersions {
    const val TLS_1 = 0u
    const val TLS_1_1 = 1u
    const val TLS_1_2 = 2u
    const val TLS_1_3 = 3u
}

typealias BackendConfigOptions = UInt

object BackendConfigOptionsValues {
    const val RESERVED = 0x1u
    const val HOST_OVERRIDE = 0x2u
    const val CONNECT_TIMEOUT = 0x4u
    const val FIRST_BYTE_TIMEOUT = 0x8u
    const val BETWEEN_BYTES_TIMEOUT = 0x10u
    const val USE_SSL = 0x20u
    const val SSL_MIN_VERSION = 0x40u
    const val SSL_MAX_VERSION = 0x80u
    const val CERT_HOSTNAME = 0x100u
    const val CA_CERT = 0x200u
    const val CIPHERS = 0x400u
    const val SNI_HOSTNAME = 0x800u
    const val DONT_POOL = 0x1000u
    const val CLIENT_CERT = 0x2000u
    const val GRPC = 0x4000u
}

typealias DynamicBackendConfigStructPointer = Pointer
data class DynamicBackendConfig(
    val hostOverride: String,
    val connectTimeoutMs: UInt,
    val firstByteTimeoutMs: UInt,
    val betweenBytesTimeoutMs: UInt,
    val sslMinVersion: TlsVersion,
    val sslMaxVersion: TlsVersion,
    val certHostname: String,
    val caCert: String,
    val ciphers: String,
    val sniHostname: String,
    val clientCertificate: String,
    val clientKey: SecretHandle,
) {
    fun toDynamicBackendConfigStructPointer(): DynamicBackendConfigStructPointer =
        withScopedMemoryAllocator { it.allocate(STRUCT_SIZE) }.also {
            with (StructWriter(it)) {
                writeString(hostOverride)
                writeUInt(connectTimeoutMs)
                writeUInt(firstByteTimeoutMs)
                writeUInt(betweenBytesTimeoutMs)
                writeUInt(sslMinVersion)
                writeUInt(sslMaxVersion)
                writeString(certHostname)
                writeString(caCert)
                writeString(ciphers)
                writeString(sniHostname)
                writeString(clientCertificate)
                writeInt(clientKey)
            }
        }

    companion object {
        private const val STRUCT_SIZE = 72
    }
}

/** TLS client certificate verified result from downstream. */
typealias ClientCertVerifyResult = UInt
object ClientCertVerifyResults {
    const val OK = 0u
    const val BAD_CERTIFICATE = 1u
    const val CERTIFICATE_REVOKED = 2u
    const val CERTIFICATE_EXPIRED = 3u
    const val UNKNOWN_CA = 4u
    const val CERTIFICATE_MISSING = 5u
    const val CERTIFICATE_UNKNOWN = 6u
}

typealias PurgeOptionsMask = UInt

const val PURGE_OPTIONS_MASK_SOFT_PURGE: PurgeOptionsMask = 1u
const val PURGE_OPTIONS_MASK_RET_BUF: PurgeOptionsMask = 2u

typealias SendErrorDetailTag = UInt
object SendErrorDetailTags {
    const val UNINITIALIZED = 0u
    const val OK = 1u
    const val DNS_TIMEOUT = 2u
    const val DNS_ERROR = 3u
    const val DESTINATION_NOT_FOUND = 4u
    const val DESTINATION_UNAVAILABLE = 5u
    const val DESTINATION_IP_UNROUTABLE = 6u
    const val CONNECTION_REFUSED = 7u
    const val CONNECTION_TERMINATED = 8u
    const val CONNECTION_TIMEOUT = 9u
    const val CONNECTION_LIMIT_REACHED = 10u
    const val TLS_CERTIFICATE_ERROR = 11u
    const val TLS_CONFIGURATION_ERROR = 12u
    const val HTTP_INCOMPLETE_RESPONSE = 13u
    const val HTTP_RESPONSE_HEADER_SECTION_TOO_LARGE = 14u
    const val HTTP_RESPONSE_BODY_TOO_LARGE = 15u
    const val HTTP_RESPONSE_TIMEOUT = 16u
    const val HTTP_RESPONSE_STATUS_INVALID = 17u
    const val HTTP_UPGRADE_FAILED = 18u
    const val HTTP_PROTOCOL_ERROR = 19u
    const val HTTP_REQUEST_CACHE_KEY_INVALID = 20u
    const val HTTP_REQUEST_URI_INVALID = 21u
    const val INTERNAL_ERROR = 22u
    const val TLS_ALERT_RECEIVED = 23u
    const val TLS_PROTOCOL_ERROR = 24u
}

/**
 * Mask representing which fields are understood by the guest, and which have been set by the host.
 *
 * When the guest calls hostcalls with a mask, it should set every bit in the mask that corresponds
 * to a defined flag. This signals the host to write only to fields with a set bit, allowing
 * forward compatibility for existing guest programs even after new fields are added to the struct.
 */
typealias SendErrorDetailMask = UInt
object SendErrorDetailMasks {
    const val RESERVED: SendErrorDetailMask = 0x1u
    const val DNS_ERROR_RCODE: SendErrorDetailMask = 0x2u
    const val DNS_ERROR_INFO_CODE: SendErrorDetailMask = 0x4u
    const val TLS_ALERT_ID: SendErrorDetailMask = 0x8u
}

typealias SendErrorDetailStructPointer = Pointer
data class SendErrorDetail(
    val tag: SendErrorDetailTag,
    val mask: SendErrorDetailMask,
    val dnsErrorRcode: UShort,
    val dnsErrorInfoCode: UShort,
    val tlsAlertId: UByte
) {
    fun toSendErrorDetailStructPointer(): SendErrorDetailStructPointer =
        withScopedMemoryAllocator { it.allocate(STRUCT_SIZE) }.also {
            with (StructWriter(it)) {
                writeUInt(tag)
                writeUInt(mask)
                writeUShort(dnsErrorRcode)
                writeUShort(dnsErrorInfoCode)
                writeUByte(tlsAlertId)
            }
        }

    companion object {
        private const val STRUCT_SIZE = 14
    }
}

typealias Blocked = UInt
typealias Rate = UInt
typealias Count = UInt
typealias Has = UInt
typealias BodyLength = ULong

// ---------------------- Module: [fastly_abi] ----------------------

@WasmImport("fastly_abi", "init")
external fun fastly_abi_init(abi_version: ULong): FastlyStatus

// ---------------------- Module: [fastly_async_io] ----------------------

/**
 * Blocks until one of the given objects is ready for I/O, or the optional timeout expires.
 *
 * Valid object handles includes bodies and pending requests. See the `async_item_handle`
 * definition for more details, including what I/O actions are associated with each handle
 * type.
 *
 * The timeout is specified in milliseconds, or 0 if no timeout is desired.
 *
 * Returns the _index_ (not handle!) of the first object that is ready, or u32::MAX if the
 * timeout expires before any objects are ready for I/O.
 */
@WasmImport("fastly_async_io", "select")
external fun fastly_async_io_select(
    hsPtr: WasiPtr<AsyncItemHandle>,
    hsLen: UInt,
    timeoutMs: UInt,
    resultPtr: WasiMutPtr<ReadyIdx>
): FastlyStatus

/**
 * Returns 1 if the given async item is "ready" for its associated I/O action, 0 otherwise.
 *
 * If an object is ready, the I/O action is guaranteed to complete without blocking.
 *
 * Valid object handles includes bodies and pending requests. See the `async_item_handle`
 * definition for more details, including what I/O actions are associated with each handle
 * type.
 */
@WasmImport("fastly_async_io", "is_ready")
external fun fastly_async_io_is_ready(
    handle: AsyncItemHandle,
    resultPtr: WasiPtr<IsDone>
): FastlyStatus

// ---------------------- Module: [fastly_backend] ----------------------

@WasmImport("fastly_backend", "exists")
external fun fastly_backend_exists(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<BackendExists>
): FastlyStatus

@WasmImport("fastly_backend", "is_healthy")
external fun fastly_backend_is_healthy(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<BackendHealth>
): FastlyStatus

@WasmImport("fastly_backend", "is_dynamic")
external fun fastly_backend_is_dynamic(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<IsDynamic>
): FastlyStatus

@WasmImport("fastly_backend", "get_host")
external fun fastly_backend_get_host(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_backend", "get_override_host")
external fun fastly_backend_get_override_host(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_backend", "get_port")
external fun fastly_backend_get_port(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<Port>
): FastlyStatus

@WasmImport("fastly_backend", "get_connect_timeout_ms")
external fun fastly_backend_get_connect_timeout_ms(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<TimeoutMs>
): FastlyStatus

@WasmImport("fastly_backend", "get_first_byte_timeout_ms")
external fun fastly_backend_get_first_byte_timeout_ms(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<TimeoutMs>
): FastlyStatus

@WasmImport("fastly_backend", "get_between_bytes_timeout_ms")
external fun fastly_backend_get_between_bytes_timeout_ms(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<TimeoutMs>
): FastlyStatus

@WasmImport("fastly_backend", "is_ssl")
external fun fastly_backend_is_ssl(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<IsSsl>
): FastlyStatus

@WasmImport("fastly_backend", "get_ssl_min_version")
external fun fastly_backend_get_ssl_min_version(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<TlsVersion>
): FastlyStatus

@WasmImport("fastly_backend", "get_ssl_max_version")
external fun fastly_backend_get_ssl_max_version(
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<TlsVersion>
): FastlyStatus

// ---------------------- Module: [fastly_cache] ----------------------
/** The outcome of a cache lookup (either bare or as part of a cache transaction) */
typealias CacheHandle = WasiHandle

typealias CacheObjectLength = ULong

typealias CacheDurationNs = ULong

typealias CacheHitCount = ULong

/** Extensible options for cache lookup operations; currently used for both `lookup` and `transaction_lookup`. */
typealias CacheLookupOptionsStructPointer = Pointer
data class CacheLookupOptions(val requestHeaders: RequestHandle) {
    fun toCacheLookupOptionsStructPointer(): CacheLookupOptionsStructPointer =
        withScopedMemoryAllocator { it.allocate(STRUCT_SIZE) }.also {
            with (StructWriter(it)) {
                writeInt(requestHeaders)
            }
        }

    companion object {
        private const val STRUCT_SIZE = 4
    }
}

typealias CacheLookupOptionsMask = UInt

const val CACHE_LOOKUP_OPTIONS_MASK_RESERVED = 1u
const val CACHE_LOOKUP_OPTIONS_MASK_REQUEST_HEADERS = 2u

/**
 * Configuration for several hostcalls that write to the cache:
 * - `insert`
 * - `transaction_insert`
 * - `transaction_insert_and_stream_back`
 * - `transaction_update`
 *
 * Some options are only allowed for certain of these hostcalls; see `cache_write_options_mask`.
 */
typealias CacheWriteOptionsStructPointer = Pointer
data class CacheWriteOptions(
    val maxAgeNs: CacheDurationNs,
    val requestHeaders: RequestHandle,
    val varyRule: String,
    val __pad32_0: UInt = 0u,
    val initialAgeNs: CacheDurationNs,
    val staleWhileRevalidateNs: CacheDurationNs,
    val surrogateKeys: String,
    val length: CacheObjectLength,
    val userMetadata: UByteArray,
) {
    fun toCacheWriteOptionsStructPointer(): CacheWriteOptionsStructPointer =
        withScopedMemoryAllocator { it.allocate(STRUCT_SIZE) }.also {
            with (StructWriter(it)) {
                writeULong(maxAgeNs)
                writeInt(requestHeaders)
                writeString(varyRule)
                writeUInt(__pad32_0)
                writeULong(initialAgeNs)
                writeULong(staleWhileRevalidateNs)
                writeString(surrogateKeys)
                writeULong(length)
                writeBytes(userMetadata.toByteArray())
            }
        }

    companion object {
        private const val STRUCT_SIZE = 64
    }
}

typealias CacheWriteOptionsMask = UInt

const val CACHE_WRITE_OPTIONS_MASK_RESERVED = 0x1u
const val CACHE_WRITE_OPTIONS_MASK_REQUEST_HEADERS = 0x2u
const val CACHE_WRITE_OPTIONS_MASK_VARY_RULE = 0x4u
const val CACHE_WRITE_OPTIONS_MASK_INITIAL_AGE_NS = 0x8u
const val CACHE_WRITE_OPTIONS_MASK_STALE_WHILE_REVALIDATE_NS = 0x10u
const val CACHE_WRITE_OPTIONS_MASK_SURROGATE_KEYS = 0x20u
const val CACHE_WRITE_OPTIONS_MASK_LENGTH = 0x40u
const val CACHE_WRITE_OPTIONS_MASK_USER_METADATA = 0x80u
const val CACHE_WRITE_OPTIONS_MASK_SENSITIVE_DATA = 0x100u

typealias CacheGetBodyOptionsMask = UInt

const val CACHE_GET_BODY_OPTIONS_MASK_RESERVED = 0x1u
const val CACHE_GET_BODY_OPTIONS_MASK_FROM = 0x2u
const val CACHE_GET_BODY_OPTIONS_MASK_TO = 0x4u

/** The status of this lookup (and potential transaction) */
typealias CacheLookupState = UInt

const val CACHE_LOOKUP_STATE_FOUND = 0x1u
const val CACHE_LOOKUP_STATE_USABLE = 0x2u
const val CACHE_LOOKUP_STATE_STALE = 0x4u
const val CACHE_LOOKUP_STATE_MUST_INSERT_OR_UPDATE = 0x8u

/**
 * Performs a non-request-collapsing cache lookup.
 *
 * Returns a result without waiting for any request collapsing that may be ongoing.
 */
@WasmImport("fastly_cache", "lookup")
external fun fastly_cache_lookup(
    cacheKeyPtr: WasiPtr<UByte>,
    cacheKeyLen: UInt,
    optionsMask: CacheLookupOptionsMask,
    options: WasiMutPtr<CacheLookupOptions>,
    resultPtr: WasiMutPtr<CacheHandle>
): FastlyStatus

/**
 * Performs a non-request-collapsing cache insertion (or update).
 *
 * The returned handle is to a streaming body that is used for writing the object into
 * the cache.
 */
@WasmImport("fastly_cache", "insert")
external fun fastly_cache_insert(
    cacheKeyPtr: WasiPtr<UByte>,
    cacheKeyLen: UInt,
    optionsMask: CacheWriteOptionsMask,
    options: CacheWriteOptionsStructPointer,
    resultPtr: WasiMutPtr<BodyHandle>
): FastlyStatus

/**
 * The entrypoint to the request-collapsing cache transaction API.
 *
 * This operation always participates in request collapsing and may return stale objects. To bypass
 * request collapsing, use `lookup` and `insert` instead.
 */
@WasmImport("fastly_cache", "transaction_lookup")
external fun fastly_cache_transaction_lookup(
    cacheKeyPtr: WasiPtr<UByte>,
    cacheKeyLen: UInt,
    optionsMask: CacheLookupOptionsMask,
    options: WasiMutPtr<CacheLookupOptions>,
    resultPtr: WasiMutPtr<CacheHandle>
): FastlyStatus

/**
 * Insert an object into the cache with the given metadata.
 *
 * Can only be used in if the cache handle state includes the `$must_insert_or_update` flag.
 *
 * The returned handle is to a streaming body that is used for writing the object into
 * the cache.
 */
@WasmImport("fastly_cache", "transaction_insert")
external fun fastly_cache_transaction_insert(
    handle: CacheHandle,
    optionsMask: CacheWriteOptionsMask,
    options:CacheWriteOptionsStructPointer,
    resultPtr: WasiMutPtr<BodyHandle>
): FastlyStatus

/**
 * Insert an object into the cache with the given metadata, and return a readable stream of the
 * bytes as they are stored.
 *
 * This helps avoid the "slow reader" problem on a teed stream, for example when a program wishes
 * to store a backend request in the cache while simultaneously streaming to a client in an HTTP
 * response.
 *
 * The returned body handle is to a streaming body that is used for writing the object _into_
 * the cache. The returned cache handle provides a separate transaction for reading out the
 * newly cached object to send elsewhere.
 */
@WasmImport("fastly_cache", "transaction_insert_and_stream_back")
external fun fastly_cache_transaction_insert_and_stream_back(
    handle: CacheHandle,
    optionsMask: CacheWriteOptionsMask,
    options:CacheWriteOptionsStructPointer,
    result0Ptr: WasiMutPtr<BodyHandle>,
    result1Ptr: WasiMutPtr<CacheHandle>
): FastlyStatus

/**
 * Update the metadata of an object in the cache without changing its data.
 *
 * Can only be used in if the cache handle state includes both of the flags:
 * - `$found`
 * - `$must_insert_or_update`
 */
@WasmImport("fastly_cache", "transaction_update")
external fun fastly_cache_transaction_update(
    handle: CacheHandle,
    optionsMask: CacheWriteOptionsMask,
    options:CacheWriteOptionsStructPointer
): FastlyStatus

/**
 * Cancel an obligation to provide an object to the cache.
 *
 * Useful if there is an error before streaming is possible, e.g. if a backend is unreachable.
 */
@WasmImport("fastly_cache", "transaction_cancel")
external fun fastly_cache_transaction_cancel(
    handle: CacheHandle
): FastlyStatus

/**
 * Close an ongoing interaction with the cache.
 *
 * If the cache handle state includes the `$must_insert_or_update` (and hence no insert or
 * update has been performed), closing the handle cancels any request collapsing, potentially
 * choosing a new waiter to perform the insertion/update.
 */
@WasmImport("fastly_cache", "close")
external fun fastly_cache_close(
    handle: CacheHandle
): FastlyStatus

@WasmImport("fastly_cache", "get_state")
external fun fastly_cache_get_state(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheLookupState>
): FastlyStatus

/**
 * Gets the user metadata of the found object, returning the `$none` error if there
 * was no found object.
 */
@WasmImport("fastly_cache", "get_user_metadata")
external fun fastly_cache_get_user_metadata(
    handle: CacheHandle,
    userMetadataOutPtr: WasiMutPtr<UByte>,
    userMetadataOutLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

/**
 * Gets a range of the found object body, returning the `$none` error if there
 * was no found object.
 *
 * The returned `body_handle` must be closed before calling this function again on the same
 * `cache_handle`.
 *
 * Note: until the CacheD protocol is adjusted to fully support this functionality,
 * the body of objects that are past the stale-while-revalidate period will not
 * be available, even when other metadata is.
 */
//@WasmImport("fastly_cache", "get_body")
//external fun fastly_cache_get_body(
//    handle: CacheHandle,
//    optionsMask: CacheGetBodyOptionsMask,
//    from: ULong,  // First field of CacheGetBodyOptions
//    to: ULong,    // Second field of CacheGetBodyOptions
//    resultPtr: WasiMutPtr<BodyHandle>
//): FastlyStatus

/**
 * Gets the content length of the found object, returning the `$none` error if there
 * was no found object, or no content length was provided.
 */
@WasmImport("fastly_cache", "get_length")
external fun fastly_cache_get_length(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheObjectLength>
): FastlyStatus

/**
 * Gets the configured max age of the found object, returning the `$none` error if there
 * was no found object.
 */
@WasmImport("fastly_cache", "get_max_age_ns")
external fun fastly_cache_get_max_age_ns(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheDurationNs>
): FastlyStatus

/**
 * Gets the configured stale-while-revalidate period of the found object, returning the
 * `$none` error if there was no found object.
 */
@WasmImport("fastly_cache", "get_stale_while_revalidate_ns")
external fun fastly_cache_get_stale_while_revalidate_ns(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheDurationNs>
): FastlyStatus

/**
 * Gets the age of the found object, returning the `$none` error if there
 * was no found object.
 */
@WasmImport("fastly_cache", "get_age_ns")
external fun fastly_cache_get_age_ns(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheDurationNs>
): FastlyStatus

/**
 * Gets the number of cache hits for the found object, returning the `$none` error if there
 * was no found object.
 */
@WasmImport("fastly_cache", "get_hits")
external fun fastly_cache_get_hits(
    handle: CacheHandle,
    resultPtr: WasiMutPtr<CacheHitCount>
): FastlyStatus

// ---------------------- Module: [fastly_config_store] ----------------------

/** A handle to a Config Store. */
typealias ConfigStoreHandle = WasiHandle

@WasmImport("fastly_config_store", "open")
external fun fastly_config_store_open(
    namePtr: WasiPtr<Char8>,
    nameLen: UInt,
    resultPtr: WasiMutPtr<ConfigStoreHandle>
): FastlyStatus

@WasmImport("fastly_config_store", "get")
external fun fastly_config_store_get(
    h: ConfigStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

// ---------------------- Module: [fastly_device_detection] ----------------------
@WasmImport("fastly_device_detection", "lookup")
external fun fastly_device_detection_lookup(
    userAgentPtr: WasiPtr<Char8>,
    userAgentLen: UInt,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

// ---------------------- Module: [fastly_dictionary] ----------------------
@WasmImport("fastly_dictionary", "open")
external fun fastly_dictionary_open(
    namePtr: WasiPtr<Char8>,
    nameLen: UInt,
    resultPtr: WasiMutPtr<DictionaryHandle>
): FastlyStatus

@WasmImport("fastly_dictionary", "get")
external fun fastly_dictionary_get(
    h: DictionaryHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

// ---------------------- Module: [fastly_dns] ----------------------
//typealias DnsLookupHandle = WasiHandle
//
///**
// * Lookup the IP addresses (IPv4 + IPv6) associated with a name.
// * Returns a handle to be consumed by lookup_wait().
// */
//@WasmImport("fastly_dns", "lookup_addr")
//external fun fastly_dns_lookup_addr(
//    namePtr: WasiPtr<Char8>,
//    nameLen: UInt,
//    resultPtr: WasiMutPtr<DnsLookupHandle>
//): FastlyStatus
//
///**
// * Lookup the names associated with an IP address.
// * Returns a handle to be consumed by lookup_wait().
// */
//@WasmImport("fastly_dns", "lookup_reverse")
//external fun fastly_dns_lookup_reverse(
//    ipPtr: WasiPtr<Char8>,
//    ipLen: UInt,
//    resultPtr: WasiMutPtr<DnsLookupHandle>
//): FastlyStatus

/**
 * Lookup the TXT records associated with a name.
 * Returns a handle to be consumed by lookup_wait().
 */
//@WasmImport("fastly_dns", "lookup_txt")
//external fun fastly_dns_lookup_txt(
//    namePtr: WasiPtr<Char8>,
//    nameLen: UInt,
//    resultPtr: WasiMutPtr<DnsLookupHandle>
//): FastlyStatus
//
///**
// * Wait for a DNS lookup to complete.
// * Returns an array of byte strings.
// */
//@WasmImport("fastly_dns", "lookup_wait")
//external fun fastly_dns_lookup_wait(
//    handle: DnsLookupHandle,
//    buf: WasiMutPtr<Char8>,
//    bufLen: UInt,
//    cursor: MultiValueCursor,
//    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
//    nwrittenOut: WasiMutPtr<UInt>
//): FastlyStatus
//
///**
// * Send a raw DNS query.
// * Returns a handle to be consumed by lookup_wait_raw().
// */
//@WasmImport("fastly_dns", "lookup_raw")
//external fun fastly_dns_lookup_raw(
//    query: WasiPtr<Char8>,
//    queryLen: UInt,
//    resultPtr: WasiMutPtr<DnsLookupHandle>
//): FastlyStatus
//
///**
// * Wait for a raw DNS response.
// * Returns a byte string.
// */
//@WasmImport("fastly_dns", "lookup_wait_raw")
//external fun fastly_dns_lookup_wait_raw(
//    handle: DnsLookupHandle,
//    response: WasiMutPtr<Char8>,
//    responseLen: UInt,
//    nwrittenOut: WasiMutPtr<UInt>
//): FastlyStatus

// ---------------------- Module: [fastly_erl] ----------------------
@WasmImport("fastly_erl", "check_rate")
external fun fastly_erl_check_rate(
    rcPtr: WasiPtr<Char8>,
    rcLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    delta: UInt,
    window: UInt,
    limit: UInt,
    pbPtr: WasiPtr<Char8>,
    pbLen: UInt,
    ttl: UInt,
    resultPtr: WasiMutPtr<Blocked>
): FastlyStatus

@WasmImport("fastly_erl", "ratecounter_increment")
external fun fastly_erl_ratecounter_increment(
    rcPtr: WasiPtr<Char8>,
    rcLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    delta: UInt
): FastlyStatus

@WasmImport("fastly_erl", "ratecounter_lookup_rate")
external fun fastly_erl_ratecounter_lookup_rate(
    rcPtr: WasiPtr<Char8>,
    rcLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    window: UInt,
    resultPtr: WasiMutPtr<Rate>
): FastlyStatus

@WasmImport("fastly_erl", "ratecounter_lookup_count")
external fun fastly_erl_ratecounter_lookup_count(
    rcPtr: WasiPtr<Char8>,
    rcLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    duration: UInt,
    resultPtr: WasiMutPtr<Count>
): FastlyStatus

@WasmImport("fastly_erl", "penaltybox_add")
external fun fastly_erl_penaltybox_add(
    pbPtr: WasiPtr<Char8>,
    pbLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    ttl: UInt
): FastlyStatus

@WasmImport("fastly_erl", "penaltybox_has")
external fun fastly_erl_penaltybox_has(
    pbPtr: WasiPtr<Char8>,
    pbLen: UInt,
    entryPtr: WasiPtr<Char8>,
    entryLen: UInt,
    resultPtr: WasiMutPtr<Has>
): FastlyStatus

// ---------------------- Module: [fastly_geo] ----------------------

@WasmImport("fastly_geo", "lookup")
external fun fastly_geo_lookup(
    addrOctets: WasiPtr<Char8>,
    addrLen: UInt,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

// ---------------------- Module: [fastly_http_body] ----------------------

@WasmImport("fastly_http_body", "append")
external fun fastly_http_body_append(
    dest: BodyHandle,
    src: BodyHandle
): FastlyStatus

@WasmImport("fastly_http_body", "new")
external fun fastly_http_body_new(
    resultPtr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_body", "read")
external fun fastly_http_body_read(
    h: BodyHandle,
    buf: WasiMutPtr<UByte>,
    bufLen: UInt,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

@WasmImport("fastly_http_body", "write")
external fun fastly_http_body_write(
    h: BodyHandle,
    bufPtr: WasiPtr<UByte>,
    bufLen: UInt,
    end: BodyWriteEnd,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

/**
 * Frees the body on the host.
 *
 * For streaming bodies, this is a _successful_ stream termination, which will signal
 * via framing that the body transfer is complete.
 */
@WasmImport("fastly_http_body", "close")
external fun fastly_http_body_close(
    h: BodyHandle
): FastlyStatus

/**
 * Frees a streaming body on the host _unsuccessfully_, so that framing makes clear that
 * the body is incomplete.
 */
@WasmImport("fastly_http_body", "abandon")
external fun fastly_http_body_abandon(
    h: BodyHandle
): FastlyStatus

@WasmImport("fastly_http_body", "trailer_append")
external fun fastly_http_body_trailer_append(
    h: BodyHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuePtr: WasiPtr<UByte>,
    valueLen: UInt
): FastlyStatus

@WasmImport("fastly_http_body", "trailer_names_get")
external fun fastly_http_body_trailer_names_get(
    h: BodyHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_body", "trailer_value_get")
external fun fastly_http_body_trailer_value_get(
    h: BodyHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_body", "trailer_values_get")
external fun fastly_http_body_trailer_values_get(
    h: BodyHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

/**
 * Returns a u64 body length if the length of a body is known, or `FastlyStatus::None`
 * otherwise.
 *
 * If the length is unknown, it is likely due to the body arising from an HTTP/1.1 message with
 * chunked encoding, an HTTP/2 or later message with no `content-length`, or being a streaming
 * body.
 *
 * Note that receiving a length from this function does not guarantee that the full number of
 * bytes can actually be read from the body. For example, when proxying a response from a
 * backend, this length may reflect the `content-length` promised in the response, but if the
 * backend connection is closed prematurely, fewer bytes may be delivered before this body
 * handle can no longer be read.
 */
@WasmImport("fastly_http_body", "known_length")
external fun fastly_http_body_known_length(
    h: BodyHandle,
    resultPtr: WasiMutPtr<BodyLength>
): FastlyStatus

// ---------------------- Module: [fastly_http_req] ----------------------
@WasmImport("fastly_http_req", "body_downstream_get")
external fun fastly_http_req_body_downstream_get(
    result0Ptr: WasiMutPtr<RequestHandle>,
    result1Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "cache_override_set")
external fun fastly_http_req_cache_override_set(
    h: RequestHandle,
    tag: CacheOverrideTag,
    ttl: UInt,
    staleWhileRevalidate: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "cache_override_v2_set")
external fun fastly_http_req_cache_override_v2_set(
    h: RequestHandle,
    tag: CacheOverrideTag,
    ttl: UInt,
    staleWhileRevalidate: UInt,
    skPtr: WasiPtr<UByte>,
    skLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_client_ip_addr")
external fun fastly_http_req_downstream_client_ip_addr(
    addrOctetsOut: WasiMutPtr<Char8>,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_client_h2_fingerprint")
external fun fastly_http_req_downstream_client_h2_fingerprint(
    h2FpOut: WasiMutPtr<Char8>,
    h2FpMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_client_request_id")
external fun fastly_http_req_downstream_client_request_id(
    reqidOut: WasiMutPtr<Char8>,
    reqidMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_client_oh_fingerprint")
external fun fastly_http_req_downstream_client_oh_fingerprint(
    ohfpOut: WasiMutPtr<Char8>,
    ohfpMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_cipher_openssl_name")
external fun fastly_http_req_downstream_tls_cipher_openssl_name(
    cipherOut: WasiMutPtr<Char8>,
    cipherMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_protocol")
external fun fastly_http_req_downstream_tls_protocol(
    protocolOut: WasiMutPtr<Char8>,
    protocolMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_client_hello")
external fun fastly_http_req_downstream_tls_client_hello(
    chelloOut: WasiMutPtr<Char8>,
    chelloMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_raw_client_certificate")
external fun fastly_http_req_downstream_tls_raw_client_certificate(
    rawClientCertOut: WasiMutPtr<Char8>,
    rawClientCertMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_client_cert_verify_result")
external fun fastly_http_req_downstream_tls_client_cert_verify_result(
    resultPtr: WasiMutPtr<ClientCertVerifyResult>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_ja3_md5")
external fun fastly_http_req_downstream_tls_ja3_md5(
    cja3Md5Out: WasiMutPtr<Char8>,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

@WasmImport("fastly_http_req", "downstream_tls_ja4")
external fun fastly_http_req_downstream_tls_ja4(
    ja4Out: WasiMutPtr<Char8>,
    ja4MaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "new")
external fun fastly_http_req_new(
    resultPtr: WasiMutPtr<RequestHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "header_names_get")
external fun fastly_http_req_header_names_get(
    h: RequestHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "original_header_names_get")
external fun fastly_http_req_original_header_names_get(
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "original_header_count")
external fun fastly_http_req_original_header_count(
    resultPtr: WasiMutPtr<HeaderCount>
): FastlyStatus

@WasmImport("fastly_http_req", "header_value_get")
external fun fastly_http_req_header_value_get(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "header_values_get")
external fun fastly_http_req_header_values_get(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "header_values_set")
external fun fastly_http_req_header_values_set(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuesPtr: WasiPtr<Char8>,
    valuesLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "header_insert")
external fun fastly_http_req_header_insert(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuePtr: WasiPtr<UByte>,
    valueLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "header_append")
external fun fastly_http_req_header_append(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuePtr: WasiPtr<UByte>,
    valueLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "header_remove")
external fun fastly_http_req_header_remove(
    h: RequestHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "method_get")
external fun fastly_http_req_method_get(
    h: RequestHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "method_set")
external fun fastly_http_req_method_set(
    h: RequestHandle,
    methodPtr: WasiPtr<Char8>,
    methodLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "uri_get")
external fun fastly_http_req_uri_get(
    h: RequestHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_req", "uri_set")
external fun fastly_http_req_uri_set(
    h: RequestHandle,
    uriPtr: WasiPtr<Char8>,
    uriLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "version_get")
external fun fastly_http_req_version_get(
    h: RequestHandle,
    resultPtr: WasiMutPtr<HttpVersion>
): FastlyStatus

@WasmImport("fastly_http_req", "version_set")
external fun fastly_http_req_version_set(
    h: RequestHandle,
    version: HttpVersion
): FastlyStatus

@WasmImport("fastly_http_req", "send")
external fun fastly_http_req_send(
    h: RequestHandle,
    b: BodyHandle,
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    result0Ptr: WasiMutPtr<ResponseHandle>,
    result1Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "send_v2")
external fun fastly_http_req_send_v2(
    h: RequestHandle,
    b: BodyHandle,
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    errorDetail: WasiMutPtr<SendErrorDetail>,
    result0Ptr: WasiMutPtr<ResponseHandle>,
    result1Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "send_async")
external fun fastly_http_req_send_async(
    h: RequestHandle,
    b: BodyHandle,
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<PendingRequestHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "send_async_streaming")
external fun fastly_http_req_send_async_streaming(
    h: RequestHandle,
    b: BodyHandle,
    backendPtr: WasiPtr<Char8>,
    backendLen: UInt,
    resultPtr: WasiMutPtr<PendingRequestHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_poll")
external fun fastly_http_req_pending_req_poll(
    h: PendingRequestHandle,
    result0Ptr: WasiMutPtr<IsDone>,
    result1Ptr: WasiMutPtr<ResponseHandle>,
    result2Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_poll_v2")
external fun fastly_http_req_pending_req_poll_v2(
    h: PendingRequestHandle,
    errorDetail: WasiMutPtr<SendErrorDetail>,
    result0Ptr: WasiMutPtr<IsDone>,
    result1Ptr: WasiMutPtr<ResponseHandle>,
    result2Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_wait")
external fun fastly_http_req_pending_req_wait(
    h: PendingRequestHandle,
    result0Ptr: WasiMutPtr<ResponseHandle>,
    result1Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_wait_v2")
external fun fastly_http_req_pending_req_wait_v2(
    h: PendingRequestHandle,
    errorDetail: WasiMutPtr<SendErrorDetail>,
    result0Ptr: WasiMutPtr<ResponseHandle>,
    result1Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_select")
external fun fastly_http_req_pending_req_select(
    hsPtr: WasiPtr<PendingRequestHandle>,
    hsLen: UInt,
    result0Ptr: WasiMutPtr<DoneIdx>,
    result1Ptr: WasiMutPtr<ResponseHandle>,
    result2Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_http_req", "pending_req_select_v2")
external fun fastly_http_req_pending_req_select_v2(
    hsPtr: WasiPtr<PendingRequestHandle>,
    hsLen: UInt,
    errorDetail: WasiMutPtr<SendErrorDetail>,
    result0Ptr: WasiMutPtr<DoneIdx>,
    result1Ptr: WasiMutPtr<ResponseHandle>,
    result2Ptr: WasiMutPtr<BodyHandle>
): FastlyStatus

/**
 * Returns whether or not the original client request arrived with a
 * Fastly-Key belonging to a user with the rights to purge content on this
 * service.
 */
@WasmImport("fastly_http_req", "fastly_key_is_valid")
external fun fastly_http_req_fastly_key_is_valid(
    resultPtr: WasiMutPtr<IsValid>
): FastlyStatus

@WasmImport("fastly_http_req", "close")
external fun fastly_http_req_close(
    h: RequestHandle
): FastlyStatus

@WasmImport("fastly_http_req", "auto_decompress_response_set")
external fun fastly_http_req_auto_decompress_response_set(
    h: RequestHandle,
    encodings: ContentEncodings
): FastlyStatus

@WasmImport("fastly_http_req", "upgrade_websocket")
external fun fastly_http_req_upgrade_websocket(
    backendNamePtr: WasiPtr<Char8>,
    backendNameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "redirect_to_websocket_proxy")
external fun fastly_http_req_redirect_to_websocket_proxy(
    backendNamePtr: WasiPtr<Char8>,
    backendNameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "redirect_to_grip_proxy")
external fun fastly_http_req_redirect_to_grip_proxy(
    backendNamePtr: WasiPtr<Char8>,
    backendNameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "redirect_to_websocket_proxy_v2")
external fun fastly_http_req_redirect_to_websocket_proxy_v2(
    h: RequestHandle,
    backendNamePtr: WasiPtr<Char8>,
    backendNameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_req", "redirect_to_grip_proxy_v2")
external fun fastly_http_req_redirect_to_grip_proxy_v2(
    h: RequestHandle,
    backendNamePtr: WasiPtr<Char8>,
    backendNameLen: UInt
): FastlyStatus

/**
 * Adjust how this requests's framing headers are determined.
 */
@WasmImport("fastly_http_req", "framing_headers_mode_set")
external fun fastly_http_req_framing_headers_mode_set(
    h: RequestHandle,
    mode: FramingHeadersMode
): FastlyStatus

/**
 * Create a backend for later use
 */
@WasmImport("fastly_http_req", "register_dynamic_backend")
external fun fastly_http_req_register_dynamic_backend(
    namePrefixPtr: WasiPtr<Char8>,
    namePrefixLen: UInt,
    targetPtr: WasiPtr<Char8>,
    targetLen: UInt,
    backendConfigMask: BackendConfigOptions,
    backendConfiguration: DynamicBackendConfigStructPointer
): FastlyStatus

// ---------------------- Module: [fastly_http_resp] ----------------------
@WasmImport("fastly_http_resp", "new")
external fun fastly_http_resp_new(
    resultPtr: WasiMutPtr<ResponseHandle>
): FastlyStatus

@WasmImport("fastly_http_resp", "header_names_get")
external fun fastly_http_resp_header_names_get(
    h: ResponseHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_resp", "header_value_get")
external fun fastly_http_resp_header_value_get(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    value: WasiMutPtr<Char8>,
    valueMaxLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_resp", "header_values_get")
external fun fastly_http_resp_header_values_get(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    cursor: MultiValueCursor,
    endingCursorOut: WasiMutPtr<MultiValueCursorResult>,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_http_resp", "header_values_set")
external fun fastly_http_resp_header_values_set(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuesPtr: WasiPtr<Char8>,
    valuesLen: UInt
): FastlyStatus

@WasmImport("fastly_http_resp", "header_insert")
external fun fastly_http_resp_header_insert(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuePtr: WasiPtr<UByte>,
    valueLen: UInt
): FastlyStatus

@WasmImport("fastly_http_resp", "header_append")
external fun fastly_http_resp_header_append(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    valuePtr: WasiPtr<UByte>,
    valueLen: UInt
): FastlyStatus

@WasmImport("fastly_http_resp", "header_remove")
external fun fastly_http_resp_header_remove(
    h: ResponseHandle,
    namePtr: WasiPtr<UByte>,
    nameLen: UInt
): FastlyStatus

@WasmImport("fastly_http_resp", "version_get")
external fun fastly_http_resp_version_get(
    h: ResponseHandle,
    resultPtr: WasiMutPtr<HttpVersion>
): FastlyStatus

@WasmImport("fastly_http_resp", "version_set")
external fun fastly_http_resp_version_set(
    h: ResponseHandle,
    version: HttpVersion
): FastlyStatus

@WasmImport("fastly_http_resp", "send_downstream")
external fun fastly_http_resp_send_downstream(
    h: ResponseHandle,
    b: BodyHandle,
    streaming: UInt
): FastlyStatus

@WasmImport("fastly_http_resp", "status_get")
external fun fastly_http_resp_status_get(
    h: ResponseHandle,
    resultPtr: WasiMutPtr<HttpStatus>
): FastlyStatus

@WasmImport("fastly_http_resp", "status_set")
external fun fastly_http_resp_status_set(
    h: ResponseHandle,
    status: HttpStatus
): FastlyStatus

@WasmImport("fastly_http_resp", "close")
external fun fastly_http_resp_close(
    h: ResponseHandle
): FastlyStatus

/**
 * Adjust how this response's framing headers are determined.
 */
@WasmImport("fastly_http_resp", "framing_headers_mode_set")
external fun fastly_http_resp_framing_headers_mode_set(
    h: ResponseHandle,
    mode: FramingHeadersMode
): FastlyStatus

/**
 * Adjust the response's connection reuse mode.
 */
@WasmImport("fastly_http_resp", "http_keepalive_mode_set")
external fun fastly_http_resp_http_keepalive_mode_set(
    h: ResponseHandle,
    mode: HttpKeepaliveMode
): FastlyStatus

// ---------------------- Module: [fastly_kv] ----------------------
typealias KvStoreHandle = WasiHandle

//@WasmImport("fastly_kv", "open")
//external fun fastly_kv_open(
//    namePtr: WasiPtr<Char8>,
//    nameLen: UInt,
//    resultPtr: WasiMutPtr<KvStoreHandle>
//): FastlyStatus
//
//@WasmImport("fastly_kv", "lookup")
//external fun fastly_kv_lookup(
//    store: KvStoreHandle,
//    keyPtr: WasiPtr<UByte>,
//    keyLen: UInt,
//    optBodyHandleOut: WasiMutPtr<BodyHandle>
//): FastlyStatus
//
//@WasmImport("fastly_kv", "insert")
//external fun fastly_kv_insert(
//    store: KvStoreHandle,
//    keyPtr: WasiPtr<UByte>,
//    keyLen: UInt,
//    bodyHandle: BodyHandle,
//    maxAge: UInt,
//    resultPtr: WasiMutPtr<Inserted>
//): FastlyStatus

// ---------------------- Module: [fastly_log] ----------------------
@WasmImport("fastly_log", "endpoint_get")
external fun fastly_log_endpoint_get(
    namePtr: WasiPtr<UByte>,
    nameLen: UInt,
    resultPtr: WasiMutPtr<EndpointHandle>
): FastlyStatus

@WasmImport("fastly_log", "write")
external fun fastly_log_write(
    h: EndpointHandle,
    msgPtr: WasiPtr<UByte>,
    msgLen: UInt,
    resultPtr: WasiMutPtr<NumBytes>
): FastlyStatus

// ---------------------- Module: [fastly_object_store] ----------------------
@WasmImport("fastly_object_store", "open")
external fun fastly_object_store_open(
    namePtr: WasiPtr<Char8>,
    nameLen: UInt,
    resultPtr: WasiMutPtr<ObjectStoreHandle>
): FastlyStatus

@WasmImport("fastly_object_store", "lookup")
external fun fastly_object_store_lookup(
    store: ObjectStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    bodyHandleOut: WasiMutPtr<BodyHandle>
): FastlyStatus

@WasmImport("fastly_object_store", "lookup_async")
external fun fastly_object_store_lookup_async(
    store: ObjectStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    pendingHandleOut: WasiMutPtr<PendingObjectStoreLookupHandle>
): FastlyStatus

@WasmImport("fastly_object_store", "pending_lookup_wait")
external fun fastly_object_store_pending_lookup_wait(
    pendingObjstrHandle: PendingObjectStoreLookupHandle,
    bodyHandleOut: WasiMutPtr<BodyHandle>
): FastlyStatus

//@WasmImport("fastly_object_store", "lookup_as_fd")
//external fun fastly_object_store_lookup_as_fd(
//    store: ObjectStoreHandle,
//    keyPtr: WasiPtr<Char8>,
//    keyLen: UInt,
//    fdOut: WasiMutPtr<UInt>
//): FastlyStatus

@WasmImport("fastly_object_store", "insert")
external fun fastly_object_store_insert(
    store: ObjectStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    bodyHandle: BodyHandle
): FastlyStatus

@WasmImport("fastly_object_store", "insert_async")
external fun fastly_object_store_insert_async(
    store: ObjectStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    bodyHandle: BodyHandle,
    pendingHandleOut: WasiMutPtr<PendingObjectStoreInsertHandle>
): FastlyStatus

@WasmImport("fastly_object_store", "pending_insert_wait")
external fun fastly_object_store_pending_insert_wait(
    pendingObjstrHandle: PendingObjectStoreInsertHandle
): FastlyStatus

@WasmImport("fastly_object_store", "delete_async")
external fun fastly_object_store_delete_async(
    store: ObjectStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    pendingHandleOut: WasiMutPtr<PendingObjectStoreDeleteHandle>
): FastlyStatus

@WasmImport("fastly_object_store", "pending_delete_wait")
external fun fastly_object_store_pending_delete_wait(
    pendingObjstrHandle: PendingObjectStoreDeleteHandle
): FastlyStatus

// ---------------------- Module: [fastly_secret_store] ----------------------
@WasmImport("fastly_secret_store", "open")
external fun fastly_secret_store_open(
    namePtr: WasiPtr<Char8>,
    nameLen: UInt,
    resultPtr: WasiMutPtr<SecretStoreHandle>
): FastlyStatus

@WasmImport("fastly_secret_store", "get")
external fun fastly_secret_store_get(
    store: SecretStoreHandle,
    keyPtr: WasiPtr<Char8>,
    keyLen: UInt,
    resultPtr: WasiMutPtr<SecretHandle>
): FastlyStatus

@WasmImport("fastly_secret_store", "plaintext")
external fun fastly_secret_store_plaintext(
    secret: SecretHandle,
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    nwrittenOut: WasiMutPtr<UInt>
): FastlyStatus

@WasmImport("fastly_secret_store", "from_bytes")
external fun fastly_secret_store_from_bytes(
    buf: WasiMutPtr<Char8>,
    bufLen: UInt,
    resultPtr: WasiMutPtr<SecretHandle>
): FastlyStatus

// ---------------------- Module: [fastly_uap] ----------------------
@WasmImport("fastly_uap", "parse")
external fun fastly_uap_parse(
    userAgentPtr: WasiPtr<Char8>,
    userAgentLen: UInt,
    family: WasiMutPtr<Char8>,
    familyLen: UInt,
    familyNwrittenOut: WasiMutPtr<UInt>,
    major: WasiMutPtr<Char8>,
    majorLen: UInt,
    majorNwrittenOut: WasiMutPtr<UInt>,
    minor: WasiMutPtr<Char8>,
    minorLen: UInt,
    minorNwrittenOut: WasiMutPtr<UInt>,
    patch: WasiMutPtr<Char8>,
    patchLen: UInt,
    patchNwrittenOut: WasiMutPtr<UInt>
): FastlyStatus
