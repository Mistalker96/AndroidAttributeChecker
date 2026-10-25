package com.mixedsignals.checker.domain.integrity

import java.security.MessageDigest

/**
 * Nhật ký minh bạch cục bộ: chuỗi băm chỉ-thêm (append-only) các APK đã kiểm trên máy này.
 * Mục đích giống transparency log công khai: phát hiện "split-view" — cùng package, cùng phiên bản,
 * cùng khóa ký nhưng NỘI DUNG khác nhau (ai đó phát hành bản khác cho riêng bạn).
 */
data class LocalLogEntry(
    val seq: Long,
    val time: Long,
    val packageName: String,
    val versionCode: Long,
    val fileSha256: String,
    val signers: Set<String>,
    val prevHash: String,
    val hash: String,
)

object LocalLog {
    const val GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"

    fun entryHash(prev: String, seq: Long, time: Long, pkg: String, vc: Long, sha: String, signers: Set<String>): String {
        val canonical = "$prev|$seq|$time|$pkg|$vc|$sha|${signers.sorted().joinToString(",")}"
        return MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun append(log: List<LocalLogEntry>, time: Long, pkg: String, vc: Long, sha: String, signers: Set<String>): LocalLogEntry {
        val prev = log.lastOrNull()?.hash ?: GENESIS
        val seq = (log.lastOrNull()?.seq ?: 0) + 1
        return LocalLogEntry(seq, time, pkg, vc, sha, signers, prev, entryHash(prev, seq, time, pkg, vc, sha, signers))
    }

    /** Chuỗi còn nguyên vẹn (không bị sửa/xóa giữa chừng)? Trả về số thứ tự bản ghi hỏng đầu tiên, hoặc null. */
    fun firstBroken(log: List<LocalLogEntry>): Long? {
        var prev = GENESIS
        for (e in log) {
            if (e.prevHash != prev || e.hash != entryHash(e.prevHash, e.seq, e.time, e.packageName, e.versionCode, e.fileSha256, e.signers)) return e.seq
            prev = e.hash
        }
        return null
    }

    /** Kiểm file mới so với nhật ký (trước khi ghi thêm). */
    fun check(log: List<LocalLogEntry>, pkg: String, vc: Long, sha: String, signers: Set<String>): LogCheckResult {
        firstBroken(log)?.let {
            return LogCheckResult(CheckStatus.UNKNOWN, "Nhật ký cục bộ bị sửa từ bản ghi #$it: không dùng được để so sánh.")
        }
        val sameVersion = log.filter { it.packageName == pkg && it.versionCode == vc }
        val conflict = sameVersion.filter { it.fileSha256 != sha && it.signers.intersect(signers).isNotEmpty() }
        val head = log.lastOrNull()?.hash?.take(16) ?: "(trống)"
        return when {
            conflict.isNotEmpty() -> LogCheckResult(
                CheckStatus.FAIL,
                "Split-view: đã từng thấy $pkg phiên bản $vc, CÙNG khóa ký nhưng NỘI DUNG KHÁC (bản ghi #${conflict.first().seq}).",
                listOf(
                    "SHA-256 trước: ${conflict.first().fileSha256}", "SHA-256 bây giờ: $sha",
                    "Có thể là bản phát hành riêng cho bạn, hoặc cùng phiên bản đóng gói khác nhau (APK chia nhỏ vs APK đầy đủ). Hãy đối chiếu nguồn tải.",
                ),
            )
            sameVersion.any { it.fileSha256 == sha } -> LogCheckResult(
                CheckStatus.PASS, "File trùng khớp bản đã ghi trong nhật ký cục bộ (bản ghi #${sameVersion.first { it.fileSha256 == sha }.seq}).",
                listOf("Đầu chuỗi nhật ký: $head…"),
            )
            else -> LogCheckResult(
                CheckStatus.PASS, "Không có xung đột: lần đầu thấy phiên bản này, sẽ được ghi vào nhật ký cục bộ (#${(log.lastOrNull()?.seq ?: 0) + 1}).",
                listOf("Đầu chuỗi nhật ký: $head…", "Tổng ${log.size} bản ghi"),
            )
        }
    }
}
