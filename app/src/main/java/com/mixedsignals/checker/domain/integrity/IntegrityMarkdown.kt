package com.mixedsignals.checker.domain.integrity

/** Xuất báo cáo kiểm tra toàn vẹn dạng Markdown để chia sẻ. */
object IntegrityMarkdown {
    fun build(r: IntegrityReport): String = buildString {
        val a = r.input.apk
        appendLine("# Báo cáo kiểm tra toàn vẹn APK")
        appendLine()
        appendLine("**${a.label}** — `${a.packageName}` · phiên bản ${a.versionName ?: "?"} (${a.versionCode})")
        appendLine()
        appendLine("- File: ${a.fileName} (${a.fileSize} byte)")
        appendLine("- SHA-256 file: `${a.fileSha256}`")
        a.signerCerts.forEach { appendLine("- SHA-256 chứng chỉ ký: `${it.sha256}`") }
        appendLine()
        appendLine("## Kết luận: ${r.verdict.icon} ${r.verdict.label}")
        appendLine()
        r.verdictReasons.forEach { appendLine("- $it") }
        appendLine()
        appendLine("**Điểm tin cậy: ${r.score.total}/100 (${r.score.band})**")
        appendLine()
        appendLine("| Tiêu chí | Điểm | Ghi chú |")
        appendLine("|---|---:|---|")
        r.score.items.forEach { appendLine("| ${it.criterion} | ${it.earned}/${it.max} | ${esc(it.note)} |") }
        r.score.capNote?.let { appendLine(); appendLine("> $it") }
        appendLine()
        appendLine("> $DISCLAIMER")
        appendLine()
        appendLine("## Các kiểm tra")
        appendLine()
        appendLine("| Kiểm tra | Kết quả | Tóm tắt |")
        appendLine("|---|---|---|")
        r.checks.forEach { appendLine("| ${it.title} | ${it.status.icon} ${it.status.label} | ${esc(it.summary)} |") }
        appendLine()
        appendLine("## Thông tin còn thiếu so với app uy tín cơ bản")
        appendLine()
        if (r.missingBaseline.isEmpty()) appendLine("Không thiếu mục nào.")
        r.missingBaseline.forEach { appendLine("- [${it.group}] ${it.title} — ${it.hint}") }
    }

    private fun esc(s: String) = s.replace("|", "\\|").replace("\n", " ")
}
