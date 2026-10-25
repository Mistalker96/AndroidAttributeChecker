package com.mixedsignals.checker.domain.integrity

import com.mixedsignals.checker.domain.CertClassifier
import com.mixedsignals.checker.domain.CertKind
import com.mixedsignals.checker.domain.model.MarketField

/** Một tiêu chí chấm điểm: điểm đạt / điểm tối đa và lý do. */
data class ScoreItem(val criterion: String, val earned: Int, val max: Int, val note: String)

data class IntegrityScore(val total: Int, val items: List<ScoreItem>, val capNote: String?) {
    val band: String get() = when {
        total >= 80 -> "Rất tin cậy"
        total >= 60 -> "Khá tin cậy"
        total >= 40 -> "Tin cậy trung bình"
        else -> "Tin cậy thấp"
    }
}

/**
 * Tiêu chí chấm điểm (công khai, hiển thị trong app):
 *  - Điểm tin cậy toàn vẹn 0–100: 7 nhóm tiêu chí cộng lại; có trần khi gặp điều kiện nghiêm trọng.
 *  - Điểm rủi ro quyền 0–100: cộng theo từng quyền (đỏ 30, vàng 10, xanh 0), tối đa 100.
 * Điểm cho biết ĐỘ MẠNH của bằng chứng; kết luận 5 mức vẫn theo các điều kiện bắt buộc (xem IntegrityAnalyzer).
 */
object Scoring {
    const val TAMPERED_CAP = 10
    const val HIGH_RISK_CAP = 45

    val INTEGRITY_CRITERIA = listOf(
        "Chữ ký APK (20): hợp lệ và có v2 trở lên 20 · chỉ có v1 10 · không hợp lệ 0",
        "Danh tính khớp nguồn công bố (25): ≥ 2 nguồn hoặc khớp ở mức file (log Google, reproducible build, Code Transparency đã neo) 25 · 1 nguồn 15 · chỉ có Source Stamp 8 · không có 0",
        "Bằng chứng độc lập (20): transparency log (Google/Rekor) 10 · reproducible build 10 · Code Transparency đã neo 10 · ≥ 2 nguồn công bố khớp nhau 10 (tối đa 20)",
        "Chứng chỉ ký (10): đủ chuẩn 10 · thiếu ≥ 3 trường subject −5 · thuật toán/khóa yếu −3 · khóa debug/test 0",
        "Metadata developer (5): theo số trường có trên 6 trường (chưa tra được: 0)",
        "Nhất quán danh tính (15): không mạo danh 5 · không dùng chung khóa 5 · không split-view và không đổi khóa so với lần trước 5",
        "Phân phối & cấu hình (5): Source Stamp hợp lệ 3 · không debug và không HTTP 2",
        "Trần điểm: có dấu hiệu bị thay đổi → tối đa $TAMPERED_CAP · rủi ro cao → tối đa $HIGH_RISK_CAP",
        "Mức: ≥ 80 rất tin cậy · 60–79 khá · 40–59 trung bình · < 40 thấp",
    )

    val PERMISSION_CRITERIA = listOf(
        "Mỗi quyền đỏ (thông báo, tiền, mật khẩu, thông tin cá nhân): +30",
        "Mỗi quyền vàng (camera, micro, vị trí gần đúng, ảnh, Bluetooth…): +10",
        "Quyền xanh và quyền hệ thống tự thêm: 0",
        "Cảnh báo manifest: targetSdk < 23 hoặc bật debug +30 · cho phép HTTP +10",
        "Điểm tối đa 100. Màu khuyến nghị theo quyền nặng nhất: có đỏ → 🔴 · chỉ có vàng → 🟡 · còn lại → 🟢",
    )

    fun integrity(input: IntegrityInput, imp: ImpersonationResult, verdict: IntegrityVerdict, continuityBroken: Boolean): IntegrityScore {
        val apk = input.apk
        val items = mutableListOf<ScoreItem>()

        val sig = when {
            !apk.signatureVerified -> 0
            apk.schemes.any { it >= 2 } -> 20
            else -> 10
        }
        items += ScoreItem("Chữ ký APK", sig, 20, if (sig == 20) "hợp lệ, có v2+" else if (sig == 10) "chỉ có v1" else "không hợp lệ")

        val pubPass = input.sources.count { it.status == CheckStatus.PASS && it.publication }
        val logPass = input.googleLog.status == CheckStatus.PASS || input.rekor.status == CheckStatus.PASS
        val reproPass = input.repro.any { it.status == CheckStatus.PASS }
        val ctAnchored = input.codeTransparency.status == CheckStatus.PASS && input.codeTransparency.keyAnchored
        val fileLevel = input.googleLog.status == CheckStatus.PASS || reproPass || ctAnchored
        val stamp = apk.sourceStampPresent && apk.sourceStampVerified
        val identity = when {
            pubPass >= 2 || fileLevel -> 25
            pubPass == 1 -> 15
            stamp -> 8
            else -> 0
        }
        items += ScoreItem("Danh tính khớp nguồn công bố", identity, 25,
            when (identity) { 25 -> if (fileLevel) "khớp ở mức file" else "$pubPass nguồn"; 15 -> "1 nguồn"; 8 -> "chỉ có Source Stamp"; else -> "không có nguồn" })

        var ev = 0
        val evNotes = mutableListOf<String>()
        if (logPass) { ev += 10; evNotes += "log" }
        if (reproPass) { ev += 10; evNotes += "reproducible" }
        if (ctAnchored) { ev += 10; evNotes += "Code Transparency" }
        if (pubPass >= 2) { ev += 10; evNotes += "≥2 nguồn" }
        items += ScoreItem("Bằng chứng độc lập", minOf(ev, 20), 20, evNotes.joinToString().ifEmpty { "chưa có" })

        val kinds = apk.signerCerts.map { CertClassifier.classify(it) }
        val cert = when {
            apk.signerCerts.isEmpty() || CertKind.DEBUG in kinds || CertKind.AOSP_TEST in kinds -> 0
            else -> {
                var c = 10
                if (apk.signerCerts.any { it.missingRdns.size >= 3 }) c -= 5
                if (apk.signerCerts.any { it.sigAlg.contains("MD5", true) || it.sigAlg.contains("SHA1", true) ||
                        (it.keyAlg.equals("RSA", true) && (it.keySizeBits ?: 2048) < 2048) }) c -= 3
                c
            }
        }
        items += ScoreItem("Chứng chỉ ký", cert, 10, if (cert == 10) "đủ chuẩn" else if (cert == 0) "không có hoặc khóa debug/test" else "có điểm yếu")

        val m = input.market
        val meta = if (m == null || m.isEmpty) 0 else Math.round(5.0 * MarketField.entries.count { m.get(it) != null } / MarketField.entries.size).toInt()
        items += ScoreItem("Metadata developer", meta, 5, if (m == null || m.isEmpty) "chưa tra được" else "${MarketField.entries.count { m.get(it) != null }}/6 trường")

        var cons = 0
        val consNotes = mutableListOf<String>()
        if (!imp.suspected) cons += 5 else consNotes += "nghi mạo danh"
        if (!input.sharedKey.detected) cons += 5 else consNotes += "khóa dùng chung"
        if (input.localLog.status != CheckStatus.FAIL && !continuityBroken) cons += 5 else consNotes += "split-view/đổi khóa"
        items += ScoreItem("Nhất quán danh tính", cons, 15, consNotes.joinToString().ifEmpty { "không có vấn đề" })

        var dist = 0
        if (stamp) dist += 3
        if (!apk.debuggable && !apk.usesCleartextTraffic) dist += 2
        items += ScoreItem("Phân phối & cấu hình", dist, 5, listOfNotNull(if (stamp) "có Source Stamp" else "không có Source Stamp",
            if (apk.debuggable) "bật debug" else null, if (apk.usesCleartextTraffic) "cho phép HTTP" else null).joinToString())

        val raw = items.sumOf { it.earned }
        val (total, cap) = when (verdict) {
            IntegrityVerdict.TAMPERED -> minOf(raw, TAMPERED_CAP) to "Có dấu hiệu bị thay đổi: điểm tối đa $TAMPERED_CAP (điểm thô $raw)."
            IntegrityVerdict.HIGH_RISK -> minOf(raw, HIGH_RISK_CAP) to "Rủi ro cao: điểm tối đa $HIGH_RISK_CAP (điểm thô $raw)."
            else -> raw to null
        }
        return IntegrityScore(total, items, cap)
    }

    fun permissionScore(items: List<AssessedPermission>, warnings: List<Pair<RiskTier, String>>): Int {
        fun w(t: RiskTier) = when (t) { RiskTier.RED -> 30; RiskTier.YELLOW -> 10; RiskTier.GREEN -> 0 }
        return minOf(100, items.sumOf { w(it.info.tier) } + warnings.sumOf { w(it.first) })
    }
}
