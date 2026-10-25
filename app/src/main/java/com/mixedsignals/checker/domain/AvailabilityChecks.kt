package com.mixedsignals.checker.domain

import com.mixedsignals.checker.domain.model.AppSignals
import com.mixedsignals.checker.domain.model.Finding
import com.mixedsignals.checker.domain.model.FindingGroup
import com.mixedsignals.checker.domain.model.MarketField
import com.mixedsignals.checker.domain.model.RDN_LABELS
import com.mixedsignals.checker.domain.model.Severity

/** Kiểm tra độ sẵn có của tín hiệu attribution (paper §5.1, Bảng 4). */
object AvailabilityChecks {

    fun run(s: AppSignals): List<Finding> = certFindings(s) + schemeFindings(s) + marketFindings(s)

    private fun f(id: String, sev: Severity, title: String, detail: String, ref: String) =
        Finding(id, FindingGroup.AVAILABILITY, sev, title, detail, ref)

    fun certFindings(s: AppSignals): List<Finding> {
        val out = mutableListOf<Finding>()
        if (s.currentCerts.isEmpty()) {
            out += f(
                "CERT_NONE", Severity.HIGH, "Không đọc được chứng chỉ ký",
                "Không lấy được chứng chỉ nào. Mọi app Android đều phải được ký, nên đây là bất thường " +
                    "(file hỏng, hoặc định dạng chữ ký chưa hỗ trợ).", "§3",
            )
            return out
        }
        if (s.hasMultipleSigners) {
            out += f(
                "CERT_MULTI_SIGNER", Severity.LOW, "App có nhiều người ký",
                "APK được ký bởi ${s.currentCerts.size} chứng chỉ cùng lúc; khó biết chứng chỉ nào đại diện cho tác giả.",
                "§7.2",
            )
        }
        s.currentCerts.forEachIndexed { i, c ->
            val tag = if (s.currentCerts.size > 1) " (chứng chỉ ${i + 1})" else ""
            if (c.selfSigned) {
                out += f(
                    "CERT_SELF_SIGNED", Severity.INFO, "Chứng chỉ tự ký$tag",
                    "Subject = Issuer: chủ chứng chỉ tự điền thông tin, không có bên thứ ba nào xác minh. " +
                        "Điều này phổ biến trên Android (~99% app).", "§2.1",
                )
            }
            val missing = c.missingRdns
            if (missing.isNotEmpty()) {
                val sev = when {
                    missing.size >= 5 -> Severity.HIGH
                    missing.size >= 3 -> Severity.MEDIUM
                    else -> Severity.LOW
                }
                out += f(
                    "CERT_MISSING_RDN", sev, "Chứng chỉ thiếu ${missing.size}/6 trường subject$tag",
                    "Thiếu: " + missing.joinToString { "$it (${RDN_LABELS[it]})" } +
                        ". Paper ghi nhận 7–39% app thiếu từng trường này.", "§5.1",
                )
            }
            when (CertClassifier.classify(c)) {
                CertKind.DEBUG -> out += f(
                    "CERT_DEBUG", Severity.HIGH, "Ký bằng chứng chỉ debug$tag",
                    "CN=Android Debug là khóa Android SDK tự sinh khi lập trình; phát hành bằng khóa này " +
                        "trái chính sách Google và không mang thông tin tác giả.", "§3.1",
                )
                CertKind.AOSP_TEST -> out += f(
                    "CERT_AOSP_TESTKEY", Severity.HIGH, "Ký bằng khóa test công khai của AOSP$tag",
                    "Private key của khóa này đã được công khai trong mã nguồn Android, ai cũng ký được.", "§3.1",
                )
                CertKind.GOOGLE_PATTERN -> out += f(
                    "CERT_GOOGLE_PATTERN", Severity.INFO, "Subject đúng mẫu Google / Play App Signing$tag",
                    "Có thể là Google ký hộ (Play App Signing) hoặc app của chính Google. Nếu là ký hộ thì " +
                        "chứng chỉ không phản ánh tác giả thật. Chỉ dựa vào subject thì không phân biệt được.",
                    "§2.1, §5.2",
                )
                CertKind.GOOGLE_LOOKALIKE -> out += if (s.isSystemApp) {
                    // App cài sẵn trong firmware: Google có nhiều khóa cũ với subject khác mẫu
                    // (ví dụ YouTube: CN=Unknown, O=Google, Inc). Chỉ ghi nhận, không cảnh báo.
                    f(
                        "CERT_GOOGLE_LOOKALIKE", Severity.INFO, "Subject có chữ Google, khác mẫu chuẩn (app hệ thống)$tag",
                        "Subject: ${c.subjectString}. App này cài sẵn trong firmware nên nhiều khả năng là khóa riêng " +
                            "của Google; nhưng chỉ nhìn subject thì không chứng minh được (đúng kết luận của paper).",
                        "§5.2",
                    )
                } else {
                    f(
                        "CERT_GOOGLE_LOOKALIKE", Severity.MEDIUM, "Subject có chữ Google nhưng sai mẫu chuẩn$tag",
                        "Subject: ${c.subjectString}. Có thể là khóa cũ của Google, hoặc chứng chỉ do bên thứ ba " +
                            "tự đặt tên Google (paper gặp O=Google, CN=Cupid). Cần đối chiếu fingerprint với bản chính chủ.",
                        "§5.2",
                    )
                }
                CertKind.GENERIC -> out += f(
                    "CERT_GENERIC_SUBJECT", Severity.MEDIUM, "Subject chung chung, vô nghĩa$tag",
                    "CN/O là \"${c.subject["CN"].orEmpty()}\" / \"${c.subject["O"].orEmpty()}\": không cho biết ai là tác giả.",
                    "§3.1, §5.1",
                )
                CertKind.NORMAL -> Unit
            }
        }
        if (s.certHistory.size > 1) {
            out += f(
                "CERT_ROTATED", Severity.INFO, "Đã xoay khóa ký (${s.certHistory.size} chứng chỉ trong lịch sử)",
                "Chữ ký v3 cho phép thay khóa và chứng minh khóa mới kế thừa khóa cũ.", "§5.2",
            )
        }
        return out
    }

    fun schemeFindings(s: AppSignals): List<Finding> {
        val out = mutableListOf<Finding>()
        val sc = s.schemes
        if (sc.isEmpty()) return out
        val names = sc.sorted().joinToString { schemeName(it) }
        if (sc == setOf(1)) {
            out += f(
                "SCHEME_V1_ONLY", Severity.LOW, "Chỉ ký bằng scheme v1 (JAR)",
                "v1 là scheme cũ nhất, không bảo vệ toàn bộ file và không hỗ trợ xoay khóa.", "§2.1",
            )
        } else if (sc.size > 1) {
            out += f(
                "SCHEME_MULTI", Severity.INFO, "Ký bằng nhiều scheme: $names",
                "Paper: 58% app ký bằng nhiều scheme để tương thích ngược.", "§5.2",
            )
        }
        if (3 in sc || 31 in sc) {
            out += f(
                "SCHEME_V3", Severity.INFO, "Có chữ ký v3: khóa ký có thể được thay đổi",
                "v3 hỗ trợ xoay vòng chứng chỉ (paper: 23,1% app; 29,1% trên Google Play), " +
                    "nên chứng chỉ của app này có thể khác đi trong tương lai.", "§5.2",
            )
        }
        return out
    }

    fun marketFindings(s: AppSignals): List<Finding> {
        val m = s.market
        if (m == null || m.isEmpty) {
            return listOf(
                f(
                    "MARKET_NOT_COLLECTED", Severity.INFO, "Chưa có metadata từ store",
                    "Bấm \"Tra cứu Google Play\" hoặc nhập tay để kiểm tra tên developer, website, email, " +
                        "địa chỉ và privacy policy.", "§5.1",
                ),
            )
        }
        val fromPlay = m.source == "play"
        val out = mutableListOf<Finding>()
        for (field in MarketField.entries) {
            if (m.get(field) != null) continue
            val (sev, why) = when (field) {
                MarketField.DEVELOPER_NAME -> Severity.MEDIUM to
                    "Tên developer gần như luôn có trên mọi store (<0,1% thiếu); thiếu là bất thường."
                MarketField.PRIVACY_POLICY -> Severity.MEDIUM to
                    "Luật (GDPR, CCPA) yêu cầu privacy policy có thông tin pháp lý của tác giả; paper: 17,8% thiếu."
                MarketField.WEBSITE -> Severity.LOW to "Paper: 33,7% app trên Google Play không có website."
                MarketField.ADDRESS -> Severity.LOW to "Paper: 44,4% app trên Google Play không có địa chỉ."
                MarketField.EMAIL -> Severity.LOW to "Email developer là trường bắt buộc trên Google Play."
                MarketField.APP_NAME -> Severity.LOW to "Không đọc được tên app trên store."
            }
            out += f(
                "MARKET_MISSING_${field.name}",
                // Nhập tay có thể chỉ là chưa điền, nên chỉ coi là thông tin.
                if (fromPlay) sev else Severity.INFO,
                "Thiếu ${field.label.lowercase()}",
                why + if (fromPlay) "" else " (Dữ liệu nhập tay: có thể chỉ là chưa điền.)",
                "§5.1",
            )
        }
        return out
    }

    fun schemeName(s: Int): String = if (s == 31) "v3.1" else "v$s"
}
