package com.mixedsignals.checker.data.integrity

import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.Checkpoint
import com.mixedsignals.checker.domain.integrity.LogCheckResult
import com.mixedsignals.checker.domain.integrity.Merkle
import com.mixedsignals.checker.domain.integrity.SignedNote
import com.mixedsignals.checker.domain.integrity.SourceParsers
import java.io.File

/**
 * Tra transparency log "Google Product Application Transparency" (định dạng C2SP tlog-tiles, Tessera).
 * Thông số lấy từ công cụ chính thức github.com/android/android-binary-transparency (verifier.go).
 *
 * Log có hàng trăm nghìn bản ghi (~80 MB) nên app KHÔNG tải hết như công cụ trên máy tính: app quét lùi
 * từ cuối log trong một ngân sách giới hạn, rồi tự tính lại gốc Merkle và so với checkpoint đã ký.
 */
class GoogleTransparencyLog(private val cacheDir: File) {
    companion object {
        const val BASE_URL = "https://www.gstatic.com/android/binary_transparency/google1p/apk/2026/02"
        const val NOTE_KEY = "android.transparency.goog/google1p/apk/2026/1+fc654374+ATr9NQE0gvOtVfj5cCStUzdlflEp3oZoNHD8pImzPj5O"
        private const val TILE_WIDTH = 256
        private const val TILE_HEIGHT = 8

        /** Log chỉ gồm app do Google phát hành (từ 1/5/2026). */
        fun applicable(packageName: String): Boolean =
            packageName.startsWith("com.google.") || packageName.startsWith("com.android.chrome") ||
                packageName.startsWith("com.chrome.") || packageName == "com.android.vending"
    }

    private val dir = File(cacheDir, "tlog/google1p_apk_2026_02")

    fun check(
        fileSha256: String,
        packageName: String,
        versionCode: Long,
        maxBundles: Int,
        onProgress: (String) -> Unit = {},
    ): LogCheckResult {
        if (!applicable(packageName)) {
            return LogCheckResult(CheckStatus.NA, "Không áp dụng: log công khai của Google chỉ gồm app do Google phát hành (từ 1/5/2026).")
        }
        val cp: Checkpoint = try {
            onProgress("Đang tải và xác minh checkpoint của log…")
            SignedNote.verifyCheckpoint(String(Http.get("$BASE_URL/checkpoint")), NOTE_KEY)
        } catch (e: SignedNote.InvalidNote) {
            return LogCheckResult(CheckStatus.UNKNOWN, "Checkpoint của log không xác minh được: ${e.message}")
        } catch (e: Exception) {
            return LogCheckResult(CheckStatus.UNKNOWN, "Không tải được checkpoint: ${e.message}")
        }

        val payload = SourceParsers.googleApkPayload(fileSha256, packageName, versionCode).toByteArray()
        val sameVersion = "\nSHA256(APK)\n$packageName\n$versionCode"
        var foundIndex = -1L
        var sameVersionCount = 0
        val lastBundle = (cp.size - 1) / TILE_WIDTH
        var scanned = 0
        var n = lastBundle
        try {
            while (n >= 0 && scanned < maxBundles && foundIndex < 0) {
                onProgress("Đang quét log: gói ${scanned + 1}/$maxBundles (${cp.size} bản ghi)…")
                val entries = SourceParsers.parseEntryBundle(entryBundle(n, cp.size))
                for ((i, e) in entries.withIndex()) {
                    if (e.contentEquals(payload)) { foundIndex = n * TILE_WIDTH + i; break }
                    if (String(e).trimEnd().endsWith(sameVersion)) sameVersionCount++
                }
                scanned++
                n--
            }
        } catch (e: Exception) {
            return LogCheckResult(CheckStatus.UNKNOWN, "Lỗi khi tải log: ${e.message}")
        }
        val scope = "đã quét ${minOf(cp.size, scanned.toLong() * TILE_WIDTH)} bản ghi gần nhất trên tổng ${cp.size}"

        if (foundIndex < 0) {
            return if (sameVersionCount > 0) LogCheckResult(
                CheckStatus.FAIL,
                "Log có $sameVersionCount bản ghi cho $packageName phiên bản $versionCode nhưng KHÔNG bản nào khớp hash file này.",
                listOf(scope, "Payload: ${String(payload).trim().replace('\n', ' ')}"),
            ) else LogCheckResult(
                CheckStatus.UNKNOWN,
                "Không thấy file này trong phạm vi đã quét (có thể là bản cũ trước 1/5/2026 hoặc nằm sâu hơn trong log).",
                listOf(scope),
            )
        }

        onProgress("Đang tính lại gốc Merkle…")
        return try {
            val root = Merkle.rootWithLeaf(cp.size, foundIndex, Merkle.leafHash(payload)) { level, index -> storedHash(level, index, cp.size) }
            if (root.contentEquals(cp.rootHash)) LogCheckResult(
                CheckStatus.PASS,
                "File có trong transparency log của Google; đã tính lại gốc Merkle và khớp checkpoint có chữ ký.",
                listOf("Vị trí bản ghi: $foundIndex / ${cp.size}", "Origin: ${cp.origin}", scope),
            ) else LogCheckResult(
                CheckStatus.UNKNOWN,
                "Tìm thấy bản ghi nhưng gốc Merkle tính lại không khớp checkpoint (log có thể vừa cập nhật). Hãy thử lại.",
                listOf("Vị trí bản ghi: $foundIndex"),
            )
        } catch (e: Exception) {
            LogCheckResult(CheckStatus.UNKNOWN, "Lỗi khi tính bằng chứng Merkle: ${e.message}")
        }
    }

    private fun entryBundle(n: Long, treeSize: Long): ByteArray {
        val width = minOf(TILE_WIDTH.toLong(), treeSize - n * TILE_WIDTH).toInt()
        val path = "tile/entries/" + SourceParsers.tileIndexPath(n) + if (width < TILE_WIDTH) ".p/$width" else ""
        // Gói đầy đủ không bao giờ đổi nên lưu vĩnh viễn; gói cuối (chưa đầy) luôn tải mới.
        return if (width == TILE_WIDTH) Http.cached("$BASE_URL/$path", File(dir, path), -1) else Http.get("$BASE_URL/$path")
    }

    private val tileMemo = HashMap<String, ByteArray>()

    /** Hash đã lưu của cây con hoàn chỉnh ở [level], chỉ số [index], đọc từ các tile băm (tile/<L>/<N>). */
    private fun storedHash(level: Int, index: Long, treeSize: Long): ByteArray {
        val tileLevel = level / TILE_HEIGHT
        val sub = level % TILE_HEIGHT
        val count = 1 shl sub
        val first = index shl sub // chỉ số đầu tiên ở tầng tileLevel*8
        val tileN = first / TILE_WIDTH
        val offset = (first % TILE_WIDTH).toInt()
        val totalAtLevel = treeSize shr (tileLevel * TILE_HEIGHT)
        val width = minOf(TILE_WIDTH.toLong(), totalAtLevel - tileN * TILE_WIDTH).toInt()
        val path = "tile/$tileLevel/" + SourceParsers.tileIndexPath(tileN) + if (width < TILE_WIDTH) ".p/$width" else ""
        val tile = tileMemo.getOrPut(path) {
            if (width == TILE_WIDTH) Http.cached("$BASE_URL/$path", File(dir, path), -1) else Http.get("$BASE_URL/$path")
        }
        require(offset + count <= tile.size / 32) { "Tile $path thiếu hash" }
        var hashes = (0 until count).map { tile.copyOfRange((offset + it) * 32, (offset + it + 1) * 32) }
        while (hashes.size > 1) hashes = hashes.chunked(2).map { Merkle.nodeHash(it[0], it[1]) }
        return hashes[0]
    }
}
