package com.mixedsignals.checker.domain.integrity

import com.mixedsignals.checker.domain.CertClassifier
import com.mixedsignals.checker.domain.CertKind
import com.mixedsignals.checker.domain.model.MarketField

/** Ghép các bằng chứng thành danh sách kiểm tra, danh sách “app uy tín cơ bản” và kết luận 5 mức. */
object IntegrityAnalyzer {

    fun analyze(input: IntegrityInput): IntegrityReport {
        val apk = input.apk
        val permissions = PermissionCatalog.assess(apk)
        val imp = Impersonation.detect(apk.label, apk.packageName)
        val checks = buildChecks(input, imp)
        val baseline = baseline(input)
        val (verdict, reasons) = verdict(input, imp, baseline)
        val score = Scoring.integrity(input, imp, verdict, continuityBroken(input))
        return IntegrityReport(input, verdict, reasons, checks, baseline, permissions, imp, score)
    }

    // ------------------------------------------------------------------ kiểm tra

    private fun buildChecks(input: IntegrityInput, imp: ImpersonationResult): List<CheckResult> {
        val apk = input.apk
        val out = mutableListOf<CheckResult>()

        // 1. SHA-256 và chữ ký
        out += CheckResult(
            "SIGNATURE", "1. Chữ ký APK và SHA-256",
            if (apk.signatureVerified) CheckStatus.PASS else CheckStatus.FAIL,
            if (apk.signatureVerified) "Chữ ký hợp lệ: nội dung file không bị sửa sau khi ký."
            else "Chữ ký KHÔNG hợp lệ: file đã bị sửa sau khi ký hoặc bị hỏng.",
            buildList {
                add("SHA-256 file: ${apk.fileSha256}")
                add("Scheme: " + apk.schemes.sorted().joinToString { if (it == 31) "v3.1" else "v$it" }.ifEmpty { "không có" })
                apk.signerCerts.forEach { add("SHA-256 chứng chỉ ký: ${it.sha256}") }
                apk.signatureErrors.take(5).forEach { add("Lỗi: $it") }
            },
        )

        // 2. Signer khớp nguồn công bố
        val src = input.sources
        val sigStatus = when {
            src.any { it.status == CheckStatus.FAIL && it.authoritative } -> CheckStatus.FAIL
            src.any { it.status == CheckStatus.PASS && it.publication } -> CheckStatus.PASS
            src.any { it.status == CheckStatus.UNKNOWN } -> CheckStatus.UNKNOWN
            else -> CheckStatus.NA
        }
        out += CheckResult(
            "SIGNER_PUBLISHED", "2. Khóa ký khớp dữ liệu công bố",
            sigStatus,
            when (sigStatus) {
                CheckStatus.PASS -> "Khớp ${src.count { it.status == CheckStatus.PASS && it.publication }} nguồn: " +
                    src.filter { it.status == CheckStatus.PASS && it.publication }.joinToString { it.source }
                CheckStatus.FAIL -> "Khóa ký KHÁC với khóa developer công bố."
                CheckStatus.UNKNOWN -> "Không tra được nguồn công bố (lỗi mạng hoặc nguồn lỗi)."
                CheckStatus.NA -> "Không tìm thấy nguồn nào công bố khóa ký cho package này."
            },
            src.map { "${it.status.icon} ${it.source}: ${it.note}" },
        )

        // 3. Metadata
        val m = input.market
        val missing = MarketField.entries.filter { m?.get(it) == null }
        out += CheckResult(
            "METADATA", "3. Thông tin metadata của developer",
            when {
                m == null || m.isEmpty -> CheckStatus.NA
                missing.isEmpty() -> CheckStatus.PASS
                else -> CheckStatus.FAIL
            },
            when {
                m == null || m.isEmpty -> "Chưa có metadata (app không có trên Google Play hoặc chưa tra cứu)."
                missing.isEmpty() -> "Đủ 6 trường: tên app, developer, website, email, địa chỉ, privacy policy."
                else -> "Thiếu: " + missing.joinToString { it.label.lowercase() }
            },
            MarketField.entries.mapNotNull { f -> m?.get(f)?.let { "${f.label}: $it" } },
        )

        // 4. Transparency log: log Google; nếu không áp dụng/không thấy thì kiểm tra tương đương trên Sigstore Rekor.
        val g = input.googleLog
        val rk = input.rekor
        val logStatus = when {
            g.status == CheckStatus.FAIL || rk.status == CheckStatus.FAIL -> CheckStatus.FAIL
            g.status == CheckStatus.PASS || rk.status == CheckStatus.PASS -> CheckStatus.PASS
            g.status == CheckStatus.UNKNOWN || rk.status == CheckStatus.UNKNOWN -> CheckStatus.UNKNOWN
            else -> CheckStatus.NA
        }
        out += CheckResult(
            "TLOG", "4. Transparency log (cây Merkle)", logStatus,
            when {
                g.status == CheckStatus.PASS || g.status == CheckStatus.FAIL -> g.summary
                rk.status == CheckStatus.PASS -> "Không có trong log Google, nhưng có trên log công khai Sigstore Rekor: ${rk.summary}"
                else -> "Log Google: ${g.summary} · Sigstore Rekor: ${rk.summary}"
            },
            listOf("${g.status.icon} Log Google: ${g.summary}") + g.details.map { "   $it" } +
                listOf("${rk.status.icon} Sigstore Rekor: ${rk.summary}") + rk.details.map { "   $it" },
        )

        // 5. Reproducible build
        val r = input.repro
        val rStatus = when {
            r.any { it.status == CheckStatus.PASS } -> CheckStatus.PASS
            r.any { it.status == CheckStatus.FAIL } -> CheckStatus.FAIL
            r.any { it.status == CheckStatus.UNKNOWN } -> CheckStatus.UNKNOWN
            else -> CheckStatus.NA
        }
        out += CheckResult(
            "REPRO", "5. Reproducible build",
            rStatus,
            when (rStatus) {
                CheckStatus.PASS -> "Bên thứ ba đã build lại từ mã nguồn và được file giống hệt."
                CheckStatus.FAIL -> "Bên thứ ba build lại nhưng KHÔNG ra file giống hệt (chưa chắc là bị sửa: có thể do build không ổn định)."
                CheckStatus.UNKNOWN -> "Không tra được dịch vụ reproducible build."
                CheckStatus.NA -> "Không có dữ liệu reproducible build cho file này (thường gặp với app nguồn đóng)."
            },
            r.map { "${it.status.icon} ${it.source}: ${it.summary}" },
        )

        // 6. Code Transparency
        val ct = input.codeTransparency
        out += CheckResult(
            "CODE_TRANSPARENCY", "6. Code Transparency",
            ct.status, ct.summary,
            buildList {
                ct.keyFingerprint?.let { add("Khóa Code Transparency: $it" + if (ct.keyAnchored) " (đã neo)" else " (chưa neo)") }
                if (ct.checkedFiles > 0) add("Đã so ${ct.checkedFiles} file code" + if (ct.missingFiles > 0) ", ${ct.missingFiles} file nằm ở split vắng mặt" else "")
                ct.modifiedFiles.take(5).forEach { add("Bị sửa: $it") }
            },
        )

        // 7. Chứng chỉ
        val certIssues = certificateIssues(input)
        out += CheckResult(
            "CERTIFICATE", "7. Chứng chỉ ký",
            when {
                apk.signerCerts.isEmpty() -> CheckStatus.FAIL
                certIssues.any { it.second } -> CheckStatus.FAIL
                else -> CheckStatus.PASS
            },
            when {
                certIssues.isEmpty() -> "Chứng chỉ đầy đủ thông tin, thuật toán và độ dài khóa đạt chuẩn."
                certIssues.any { it.second } -> certIssues.joinToString("; ") { it.first }
                else -> "Đạt, nhưng lưu ý: " + certIssues.joinToString("; ") { it.first }
            },
            apk.signerCerts.map { "Subject: ${it.subjectString} · ${it.keyAlg} ${it.keySizeBits ?: "?"} bit · ${it.sigAlg}" } +
                apk.lineageCerts.takeIf { it.size > 1 }?.let { listOf("Lịch sử xoay khóa: ${it.size} chứng chỉ") }.orEmpty(),
        )

        // 8. Lịch sử (neo khóa lần trước)
        val prev = input.previous
        out += CheckResult(
            "HISTORY", "8. So với lần kiểm trước",
            when {
                prev == null -> CheckStatus.NA
                continuityBroken(input) -> CheckStatus.FAIL
                else -> CheckStatus.PASS
            },
            when {
                prev == null -> "Lần đầu kiểm package này; khóa ký sẽ được ghi nhớ để so cho lần sau."
                continuityBroken(input) -> "Khóa ký KHÁC lần kiểm trước và không có lineage nối với khóa cũ."
                else -> "Khóa ký trùng (hoặc kế thừa hợp lệ) khóa đã ghi nhận lần trước."
            },
        )

        // 9. Mạo danh
        out += CheckResult(
            "IMPERSONATION", "9. Phát hiện mạo danh",
            if (imp.suspected) CheckStatus.FAIL else CheckStatus.PASS,
            if (imp.suspected) imp.reason else "Không thấy dấu hiệu giả tên app phổ biến.",
        )

        // 10. Nguồn phân phối
        out += CheckResult(
            "DISTRIBUTION", "10. Nguồn phân phối",
            when {
                apk.sourceStampPresent && apk.sourceStampVerified -> CheckStatus.PASS
                apk.sourceStampPresent -> CheckStatus.FAIL
                else -> CheckStatus.NA
            },
            when {
                apk.sourceStampPresent && apk.sourceStampVerified -> "Có Source Stamp hợp lệ: APK do Google Play phân phối."
                apk.sourceStampPresent -> "Source Stamp KHÔNG hợp lệ."
                else -> "Không có Source Stamp (APK không đến trực tiếp từ Google Play hoặc store không gắn dấu)."
            },
            listOfNotNull(apk.installer?.let { "Trình cài đặt: $it" }),
        )

        // 11. Nền tảng tạo app / khóa dùng chung
        val sk = input.sharedKey
        out += CheckResult(
            "SHARED_KEY", "11. Nền tảng tạo app / khóa dùng chung",
            when {
                sk.detected -> CheckStatus.FAIL
                !sk.deviceScanned -> CheckStatus.UNKNOWN
                else -> CheckStatus.PASS
            },
            when {
                sk.builder != null -> "Khóa ký thuộc nền tảng tạo app ${sk.builder.name}: khóa nói lên nền tảng, không nói lên tác giả (paper §7.2)."
                sk.foreignSiblings.isNotEmpty() -> "Khóa ký được ${sk.foreignSiblings.size} app của developer khác trên máy dùng chung (paper §6.3). " +
                    "Các app này được Android tự cấp quyền signature của nhau."
                !sk.deviceScanned -> "Chưa quét được app trên máy để so khóa."
                else -> "Không thấy khóa ký này được app của developer khác dùng chung trên máy."
            },
            buildList {
                sk.builderReason?.let { add(it) }
                sk.foreignSiblings.take(8).forEach { add("Dùng chung khóa: ${it.label} (${it.packageName})") }
                if (sk.foreignSiblings.size > 8) add("… và ${sk.foreignSiblings.size - 8} app khác")
                if (sk.ownSiblings.isNotEmpty()) add("Cùng khóa, cùng tiền tố package (có thể cùng developer): ${sk.ownSiblings.size} app")
            },
        )

        // 12. Nhật ký minh bạch cục bộ (phát hiện split-view)
        out += CheckResult("LOCAL_LOG", "12. Nhật ký minh bạch cục bộ (split-view)", input.localLog.status, input.localLog.summary, input.localLog.details)
        return out
    }

    /** (mô tả, nghiêm trọng?) */
    private fun certificateIssues(input: IntegrityInput): List<Pair<String, Boolean>> {
        val out = mutableListOf<Pair<String, Boolean>>()
        for (c in input.apk.signerCerts) {
            when (CertClassifier.classify(c)) {
                CertKind.DEBUG -> out += "khóa debug" to true
                CertKind.AOSP_TEST -> out += "khóa test AOSP (ai cũng ký được)" to true
                else -> Unit
            }
            if (c.missingRdns.isNotEmpty()) out += "thiếu ${c.missingRdns.size}/6 trường subject" to false
            val bits = c.keySizeBits
            if (c.keyAlg.equals("RSA", true) && bits != null && bits < 2048) out += "khóa RSA $bits bit (yếu)" to false
            if (c.sigAlg.contains("MD5", true) || c.sigAlg.contains("SHA1", true)) out += "thuật toán ${c.sigAlg} (yếu)" to false
            if (c.notAfter < System.currentTimeMillis()) out += "chứng chỉ đã hết hạn" to false
        }
        return out
    }

    private fun continuityBroken(input: IntegrityInput): Boolean {
        val prev = input.previous ?: return false
        val cur = input.apk.signerFingerprints
        if (cur.isEmpty() || prev.signerFingerprints.isEmpty()) return false
        if (cur.intersect(prev.signerFingerprints).isNotEmpty()) return false
        // Xoay khóa hợp lệ: lineage hiện tại chứa khóa cũ.
        return input.apk.lineageFingerprints.intersect(prev.signerFingerprints).isEmpty()
    }

    // ------------------------------------------------------------------ app uy tín cơ bản

    fun baseline(input: IntegrityInput): List<BaselineItem> {
        val apk = input.apk
        val certs = apk.signerCerts
        val m = input.market
        val out = mutableListOf<BaselineItem>()
        val cert = "Chứng chỉ"
        out += BaselineItem(cert, "Đủ 6 trường subject (CN, O, OU, L, ST, C)", certs.isNotEmpty() && certs.all { it.missingRdns.isEmpty() }, "Developer nên điền đủ tên pháp nhân khi tạo khóa ký.")
        out += BaselineItem(cert, "Khóa mạnh (RSA ≥ 2048 bit hoặc EC)", certs.isNotEmpty() && certs.all { !it.keyAlg.equals("RSA", true) || (it.keySizeBits ?: 0) >= 2048 }, "Khóa yếu dễ bị giả mạo.")
        out += BaselineItem(cert, "Thuật toán ký SHA-256 trở lên", certs.isNotEmpty() && certs.none { it.sigAlg.contains("MD5", true) || it.sigAlg.contains("SHA1", true) }, "MD5/SHA-1 đã lỗi thời.")
        out += BaselineItem(cert, "Không dùng khóa debug hoặc khóa test", certs.isNotEmpty() && certs.none { CertClassifier.classify(it) in setOf(CertKind.DEBUG, CertKind.AOSP_TEST) }, "Bản phát hành phải ký bằng khóa riêng.")
        out += BaselineItem(cert, "Chữ ký scheme v2 trở lên", apk.schemes.any { it >= 2 }, "v1 không bảo vệ toàn bộ file.")
        out += BaselineItem(cert, "Khóa ký riêng, không dùng chung với developer khác", !input.sharedKey.detected, "Tránh nền tảng tạo app ký hộ bằng khóa chung (paper §7.2).")

        val pub = "Công bố danh tính"
        out += BaselineItem(pub, "Fingerprint khóa ký được công bố", input.sources.any { it.status == CheckStatus.PASS && it.publication }, "Developer nên công bố SHA-256 chứng chỉ trên website chính thức.")
        out += BaselineItem(pub, "Digital Asset Links (assetlinks.json) hợp lệ", input.sources.firstOrNull { it.source.startsWith("Digital Asset Links") }?.let { it.status == CheckStatus.PASS } ?: false, "Đặt /.well-known/assetlinks.json trên domain chính thức.")
        val webHost = m?.website?.let { hostOf(it) }
        val mailDomain = m?.email?.substringAfter('@', "")?.lowercase()?.ifEmpty { null }
        // Chưa có metadata (offline hoặc app không có trên Google Play) thì là "chưa biết" (null), không phải "thiếu".
        val noMarket = m == null || m.isEmpty
        out += BaselineItem(
            pub, "Website và email cùng domain",
            when {
                noMarket -> null
                webHost == null || mailDomain == null -> false
                else -> webHost.endsWith(mailDomain) || mailDomain.endsWith(registrable(webHost))
            },
            "Email dùng domain riêng đáng tin hơn email miễn phí.",
        )

        val meta = "Metadata trên store"
        for (f in listOf(MarketField.DEVELOPER_NAME, MarketField.WEBSITE, MarketField.EMAIL, MarketField.ADDRESS, MarketField.PRIVACY_POLICY)) {
            out += BaselineItem(
                meta, f.label, if (noMarket) null else m?.get(f) != null,
                if (f == MarketField.PRIVACY_POLICY) "Bắt buộc theo luật bảo vệ dữ liệu." else "Thông tin liên hệ của developer.",
            )
        }

        val tr = "Minh bạch"
        out += BaselineItem(tr, "Code Transparency", input.codeTransparency.status == CheckStatus.PASS, "Developer thêm bằng bundletool add-transparency.")
        out += BaselineItem(
            tr, "Transparency log hoặc reproducible build",
            input.googleLog.status == CheckStatus.PASS || input.rekor.status == CheckStatus.PASS || input.repro.any { it.status == CheckStatus.PASS },
            "Ghi chữ ký file lên log công khai (Sigstore: cosign sign-blob) hoặc phát hành bản build tái lập được (F-Droid, IzzyOnDroid).",
        )

        val dist = "Phân phối"
        out += BaselineItem(dist, "Phân phối qua store có kiểm duyệt (Source Stamp)", apk.sourceStampPresent && apk.sourceStampVerified, "Tải từ Google Play hoặc store có kiểm duyệt.")
        out += BaselineItem(dist, "Không bật chế độ debug", !apk.debuggable, "Bản phát hành không được debuggable.")
        out += BaselineItem(dist, "Không cho phép kết nối không mã hóa", !apk.usesCleartextTraffic, "Chỉ dùng HTTPS.")
        return out
    }

    private fun hostOf(url: String): String? =
        url.substringAfter("://", url).substringBefore('/').substringBefore(':').lowercase().removePrefix("www.").ifEmpty { null }

    private fun registrable(host: String): String = host.split('.').takeLast(2).joinToString(".")

    // ------------------------------------------------------------------ kết luận

    fun verdict(input: IntegrityInput, imp: ImpersonationResult, baseline: List<BaselineItem>): Pair<IntegrityVerdict, List<String>> {
        val apk = input.apk
        val reasons = mutableListOf<String>()

        // ❌ Có dấu hiệu bị thay đổi
        if (!apk.signatureVerified) reasons += "Chữ ký APK không hợp lệ."
        input.sources.filter { it.status == CheckStatus.FAIL && it.authoritative }.forEach { reasons += "Khóa ký khác khóa công bố tại ${it.source}." }
        if (input.googleLog.status == CheckStatus.FAIL) reasons += "Không khớp transparency log: ${input.googleLog.summary}"
        if (input.codeTransparency.status == CheckStatus.FAIL) reasons += "Code Transparency: ${input.codeTransparency.summary}"
        if (continuityBroken(input)) reasons += "Khóa ký khác lần kiểm trước, không có lineage."
        if (reasons.isNotEmpty()) return IntegrityVerdict.TAMPERED to reasons

        // 🟠 Rủi ro cao
        val certKinds = apk.signerCerts.map { CertClassifier.classify(it) }
        if (CertKind.DEBUG in certKinds) reasons += "Ký bằng khóa debug."
        if (CertKind.AOSP_TEST in certKinds) reasons += "Ký bằng khóa test công khai của AOSP."
        if (imp.suspected) reasons += "Nghi mạo danh ${imp.target?.name}."
        if (apk.debuggable) reasons += "App bật chế độ debug."
        if (input.localLog.status == CheckStatus.FAIL) reasons += "Dấu hiệu split-view: cùng phiên bản, cùng khóa nhưng nội dung khác bản đã kiểm trước."
        val missingCount = baseline.count { it.present == false }
        // Khớp transparency log hoặc khớp file đã được build lại nghĩa là CHÍNH FILE này đã được bên phát hành
        // công bố, nên cũng được tính là khớp danh tính (mạnh hơn cả so khóa ký).
        // Code Transparency với khóa đã neo cũng là danh tính của developer (như đã thống nhất).
        val ctAnchored = input.codeTransparency.status == CheckStatus.PASS && input.codeTransparency.keyAnchored
        val fileMatched = input.googleLog.status == CheckStatus.PASS || input.repro.any { it.status == CheckStatus.PASS } || ctAnchored
        val signerMatched = input.sources.any { it.status == CheckStatus.PASS && it.publication } || fileMatched
        if (!signerMatched && missingCount * 2 > baseline.size) reasons += "Thiếu $missingCount/${baseline.size} mục của một app uy tín cơ bản."
        if (reasons.isNotEmpty()) return IntegrityVerdict.HIGH_RISK to reasons

        // 🛡️ Toàn vẹn
        val evidence = mutableListOf<String>()
        if (input.googleLog.status == CheckStatus.PASS) evidence += "có trong transparency log của Google"
        // Rekor chứng minh file đã được công bố công khai (không thể làm bản riêng mà không lộ), nhưng ai cũng ghi được
        // lên Rekor nên KHÔNG tự nó chứng minh danh tính: chỉ là bằng chứng độc lập đi kèm khớp danh tính.
        if (input.rekor.status == CheckStatus.PASS) evidence += "có bản ghi công khai trên Sigstore Rekor"
        input.repro.filter { it.status == CheckStatus.PASS }.forEach { evidence += "reproducible build (${it.source})" }
        if (input.codeTransparency.status == CheckStatus.PASS && input.codeTransparency.keyAnchored) evidence += "Code Transparency đã neo khóa"
        val passSources = input.sources.filter { it.status == CheckStatus.PASS && it.publication }
        if (passSources.size >= 2) evidence += "${passSources.size} nguồn công bố khớp nhau"
        // Khóa dùng chung / nền tảng tạo app: khớp khóa không chứng minh được tác giả, nên chỉ bằng chứng
        // ở mức FILE (log, reproducible build, Code Transparency đã neo) mới đủ cho mức Toàn vẹn.
        if (input.sharedKey.detected && !fileMatched) {
            evidence.clear()
        }
        if (signerMatched && evidence.isNotEmpty()) {
            return IntegrityVerdict.VERIFIED to listOfNotNull(
                "Chữ ký hợp lệ.",
                passSources.takeIf { it.isNotEmpty() }?.let { "Khóa ký khớp: " + it.joinToString { s -> s.source } + "." },
                "Bằng chứng độc lập: " + evidence.joinToString() + ".",
            )
        }

        // 🟢 Rủi ro thấp
        val sharedNote = if (input.sharedKey.detected) {
            "Khóa ký dùng chung" + (input.sharedKey.builder?.let { " (nền tảng ${it.name})" } ?: " với app của developer khác") +
                ": khớp khóa không chứng minh được ai là tác giả."
        } else null
        if (signerMatched) return IntegrityVerdict.LOW_RISK to listOfNotNull(
            "Chữ ký hợp lệ, khóa ký khớp: " + passSources.joinToString { it.source } + ".",
            sharedNote ?: "Chưa có bằng chứng độc lập (transparency log, reproducible build, Code Transparency đã neo).",
        )
        if (apk.sourceStampPresent && apk.sourceStampVerified) return IntegrityVerdict.LOW_RISK to listOf(
            "Chữ ký hợp lệ và có Source Stamp của Google Play.",
            "Chưa đối chiếu được khóa ký với nguồn công bố của developer.",
        )

        // ⚪ Chưa có dữ liệu
        return IntegrityVerdict.NO_DATA to listOf(
            "Chữ ký hợp lệ nhưng không tìm thấy nguồn nào để đối chiếu.",
            "Hãy dán fingerprint chính thức hoặc nhập website của developer rồi kiểm lại.",
        )
    }
}
