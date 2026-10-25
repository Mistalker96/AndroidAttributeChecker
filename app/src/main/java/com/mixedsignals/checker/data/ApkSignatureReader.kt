package com.mixedsignals.checker.data

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * Đọc thông tin chữ ký trực tiếp từ file APK, không cần cài đặt:
 *  - scheme v1: có file chữ ký .SF trong thư mục META-INF của ZIP;
 *  - scheme v2 / v3 / v3.1: có khối "APK Signing Block" nằm ngay trước Central Directory.
 * Chỉ đọc phần cuối file, nên nhanh kể cả với APK lớn. Không xác minh chữ ký (việc đó Android làm khi cài).
 */
object ApkSignatureReader {
    const val ID_V2 = 0x7109871a
    const val ID_V3 = 0xf05368c0.toInt()
    const val ID_V31 = 0x1b93ad61

    private val MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    private const val EOCD_SIG = 0x06054b50

    data class Result(
        /** 1, 2, 3, 31 (= v3.1). */
        val schemes: Set<Int>,
        /** Chứng chỉ của signer đầu tiên, ưu tiên v3.1 > v3 > v2 > v1. */
        val signerCerts: List<X509Certificate>,
        val signerCount: Int,
    )

    fun read(file: File): Result {
        val schemes = sortedSetOf<Int>()
        var certs: List<X509Certificate> = emptyList()
        var signerCount = 0

        val blocks = runCatching { readSigningBlock(file) }.getOrDefault(emptyMap())
        for ((id, scheme) in listOf(ID_V31 to 31, ID_V3 to 3, ID_V2 to 2)) {
            val value = blocks[id] ?: continue
            schemes += scheme
            if (certs.isEmpty()) {
                val parsed = runCatching { parseSchemeBlockCerts(value) }.getOrNull()
                if (parsed != null && parsed.second.isNotEmpty()) {
                    signerCount = parsed.first
                    certs = parsed.second
                }
            }
        }

        val v1 = runCatching { readV1(file) }.getOrNull()
        if (v1 != null && v1.first) {
            schemes += 1
            if (certs.isEmpty()) {
                certs = v1.second
                signerCount = v1.third
            }
        }
        return Result(schemes, certs, signerCount)
    }

    /** Trả về map ID -> giá trị của các cặp trong APK Signing Block; rỗng nếu không có khối này. */
    fun readSigningBlock(file: File): Map<Int, ByteBuffer> {
        RandomAccessFile(file, "r").use { raf ->
            val len = raf.length()
            val (cdOffset, _) = findCentralDirectory(raf, len) ?: return emptyMap()
            if (cdOffset < 32) return emptyMap()
            val footer = ByteArray(24)
            raf.seek(cdOffset - 24)
            raf.readFully(footer)
            if (!footer.copyOfRange(8, 24).contentEquals(MAGIC)) return emptyMap()
            val sizeInFooter = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
            if (sizeInFooter < 24 || sizeInFooter > Int.MAX_VALUE - 8) return emptyMap()
            val total = (sizeInFooter + 8).toInt()
            val start = cdOffset - total
            if (start < 0) return emptyMap()
            val block = ByteArray(total)
            raf.seek(start)
            raf.readFully(block)
            val buf = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
            val sizeInHeader = buf.getLong(0)
            if (sizeInHeader != sizeInFooter) return emptyMap()
            // Các cặp nằm giữa trường size đầu (8 byte) và phần đuôi (size 8 byte + magic 16 byte).
            val pairs = ByteBuffer.wrap(block, 8, total - 8 - 24).slice().order(ByteOrder.LITTLE_ENDIAN)
            val out = LinkedHashMap<Int, ByteBuffer>()
            while (pairs.remaining() >= 8) {
                val pairLen = pairs.long
                if (pairLen < 4 || pairLen > pairs.remaining()) break
                val id = pairs.int
                val valueLen = (pairLen - 4).toInt()
                val value = pairs.slice().order(ByteOrder.LITTLE_ENDIAN)
                value.limit(valueLen)
                out[id] = value
                pairs.position(pairs.position() + valueLen)
            }
            return out
        }
    }

    /** Tìm End Of Central Directory; trả về (offset, size) của Central Directory. */
    private fun findCentralDirectory(raf: RandomAccessFile, len: Long): Pair<Long, Long>? {
        val maxScan = minOf(len, 22L + 0xffff)
        val tail = ByteArray(maxScan.toInt())
        raf.seek(len - maxScan)
        raf.readFully(tail)
        val bb = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN)
        for (i in tail.size - 22 downTo 0) {
            if (bb.getInt(i) == EOCD_SIG) {
                val commentLen = bb.getShort(i + 20).toInt() and 0xffff
                if (i + 22 + commentLen != tail.size) continue
                val cdSize = bb.getInt(i + 12).toLong() and 0xffffffffL
                val cdOffset = bb.getInt(i + 16).toLong() and 0xffffffffL
                return cdOffset to cdSize
            }
        }
        return null
    }

    private fun ByteBuffer.lengthPrefixed(): ByteBuffer {
        val n = int
        require(n in 0..remaining()) { "Độ dài không hợp lệ: $n" }
        val out = slice().order(ByteOrder.LITTLE_ENDIAN)
        out.limit(n)
        position(position() + n)
        return out
    }

    /**
     * Khối v2/v3: dãy signer (có tiền tố độ dài). Mỗi signer bắt đầu bằng "signed data",
     * trong đó trường thứ hai là dãy chứng chỉ X.509 (DER). Trả về (số signer, chứng chỉ của signer đầu).
     */
    fun parseSchemeBlockCerts(value: ByteBuffer): Pair<Int, List<X509Certificate>> {
        val v = value.duplicate().order(ByteOrder.LITTLE_ENDIAN)
        val signers = v.lengthPrefixed()
        var count = 0
        var first: List<X509Certificate> = emptyList()
        val cf = CertificateFactory.getInstance("X.509")
        while (signers.hasRemaining()) {
            val signer = signers.lengthPrefixed()
            count++
            if (first.isNotEmpty()) continue
            val signedData = signer.lengthPrefixed()
            signedData.lengthPrefixed() // digests
            val certSeq = signedData.lengthPrefixed()
            val list = mutableListOf<X509Certificate>()
            while (certSeq.hasRemaining()) {
                val der = certSeq.lengthPrefixed()
                val bytes = ByteArray(der.remaining()).also { der.get(it) }
                list += cf.generateCertificate(bytes.inputStream()) as X509Certificate
            }
            first = list
        }
        return count to first
    }

    /** v1 (JAR signing): (có chữ ký v1?, chứng chỉ của signer đầu, số signer). */
    private fun readV1(file: File): Triple<Boolean, List<X509Certificate>, Int> {
        ZipFile(file).use { zip ->
            val names = zip.entries().asSequence().map { it.name }.toList()
            val sf = names.filter { it.startsWith("META-INF/", true) && it.endsWith(".SF", true) }
            if (sf.isEmpty()) return Triple(false, emptyList(), 0)
            val blocks = names.filter {
                it.startsWith("META-INF/", true) &&
                    (it.endsWith(".RSA", true) || it.endsWith(".DSA", true) || it.endsWith(".EC", true))
            }.sorted()
            val cf = CertificateFactory.getInstance("X.509")
            val certs = blocks.firstOrNull()?.let { name ->
                zip.getInputStream(zip.getEntry(name)).use { input ->
                    // Khối chữ ký v1 là PKCS#7; chứng chỉ ký nằm đầu tiên.
                    cf.generateCertificates(input).filterIsInstance<X509Certificate>().take(1)
                }
            }.orEmpty()
            return Triple(true, certs, blocks.size)
        }
    }
}
