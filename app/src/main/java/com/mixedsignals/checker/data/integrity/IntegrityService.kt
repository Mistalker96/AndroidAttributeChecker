package com.mixedsignals.checker.data.integrity

import android.content.Context
import com.mixedsignals.checker.data.PlayStoreSource
import com.mixedsignals.checker.domain.integrity.AnchorRecord
import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.CodeTransparency
import com.mixedsignals.checker.domain.integrity.IntegrityAnalyzer
import com.mixedsignals.checker.domain.integrity.IntegrityInput
import com.mixedsignals.checker.domain.integrity.IntegrityReport
import com.mixedsignals.checker.domain.integrity.LocalLog
import com.mixedsignals.checker.domain.integrity.LogCheckResult
import com.mixedsignals.checker.domain.integrity.ReproResult
import com.mixedsignals.checker.domain.integrity.SharedKeys
import com.mixedsignals.checker.domain.integrity.SourceParsers
import com.mixedsignals.checker.domain.integrity.SourceResult
import com.mixedsignals.checker.domain.model.MarketSignals
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Thông tin người dùng cung cấp thêm cho lần kiểm. */
data class IntegrityOptions(
    /** Fingerprint SHA-256 chính thức của khóa ký APK (dán từ trang của developer). */
    val officialFingerprints: String = "",
    /** SHA-256 của file APK do developer công bố (checksum trên trang tải). */
    val officialFileChecksum: String = "",
    /** Website/domain chính thức của developer (để đọc Digital Asset Links). */
    val website: String = "",
    /** Fingerprint khóa Code Transparency do developer công bố. */
    val ctKeyFingerprints: String = "",
    val online: Boolean = true,
    val checkGooglePlay: Boolean = true,
    val checkIzzy: Boolean = true,
    val checkRekor: Boolean = true,
    val googleLogBundles: Int = 300,
)

/** Điều phối toàn bộ phép kiểm cho một APK. */
class IntegrityService(private val context: Context) {
    private val inspector = ApkInspector(context)
    private val cache = File(context.cacheDir, "sources")
    private val anchors = AnchorStore(File(context.filesDir, "anchors.json"))
    private val tlog = GoogleTransparencyLog(context.cacheDir)
    private val localLog = LocalLogStore(File(context.filesDir, "local_transparency_log.json"))

    fun installedApps(includeSystem: Boolean) = inspector.installedApps(includeSystem)
    fun prepareFromUri(uri: android.net.Uri, name: String) = inspector.prepareFromUri(uri, name)
    fun prepareInstalled(pkg: String) = inspector.prepareInstalled(pkg)

    fun run(bundle: ApkBundle, opt: IntegrityOptions, progress: (String) -> Unit): IntegrityReport {
        progress("Đang xác minh chữ ký và đọc manifest…")
        val ins = inspector.inspect(bundle)
        val apk = ins.evidence
        val pkg = apk.packageName
        val signer = apk.signerFingerprints
        val previous = anchors.get(pkg)

        // ---- Nguồn công bố khóa ký
        val sources = mutableListOf<SourceResult>()
        val official = SourceParsers.parseUserFingerprints(opt.officialFingerprints)
        if (official.isNotEmpty()) {
            sources += SourceResult(
                "Fingerprint bạn nhập (trang chính thức)",
                if (official.intersect(signer).isNotEmpty()) CheckStatus.PASS else CheckStatus.FAIL,
                official,
                if (official.intersect(signer).isNotEmpty()) "khớp khóa ký" else "KHÔNG khớp khóa ký của APK",
            )
        }
        val checksum = SourceParsers.normalizeFingerprint(opt.officialFileChecksum)
        if (checksum.isNotEmpty()) {
            sources += SourceResult(
                "Checksum file do developer công bố",
                if (checksum == apk.fileSha256) CheckStatus.PASS else CheckStatus.FAIL,
                note = if (checksum == apk.fileSha256) "SHA-256 file khớp" else "SHA-256 file KHÔNG khớp",
            )
        }

        var market: MarketSignals? = null
        if (opt.online && opt.checkGooglePlay && !pkg.startsWith("(")) {
            progress("Đang tra cứu Google Play…")
            market = runCatching { PlayStoreSource.fetch(pkg) }.getOrNull()
        }

        if (opt.online) {
            // Digital Asset Links trên domain chính thức (người dùng nhập, hoặc website trên Google Play).
            val domain = hostOf(opt.website) ?: hostOf(market?.website)
            if (domain != null) {
                progress("Đang đọc Digital Asset Links của $domain…")
                sources += assetLinks(domain, pkg, signer)
            }
            progress("Đang tra F-Droid…")
            sources += fdroidSigner(pkg, signer)
        }
        if (previous != null) {
            val same = previous.signerFingerprints.intersect(signer).isNotEmpty() ||
                apk.lineageFingerprints.intersect(previous.signerFingerprints).isNotEmpty()
            // Lịch sử trên máy chỉ là "tin ở lần đầu", không phải nguồn công bố; kết quả FAIL đã được xét ở mục 8.
            sources += SourceResult(
                "Lần kiểm trước trên máy này",
                if (same) CheckStatus.PASS else CheckStatus.NA,
                previous.signerFingerprints,
                if (same) "trùng khóa đã ghi nhận" else "khác khóa đã ghi nhận (xem mục 8)",
                authoritative = false,
                publication = false,
            )
        }

        // ---- Reproducible build
        val repro = mutableListOf<ReproResult>()
        if (opt.online) {
            progress("Đang tra reproducible build (F-Droid)…")
            repro += fdroidRepro(pkg, apk.versionCode, apk.fileSha256)
            if (opt.checkIzzy) {
                progress("Đang tra reproducible build (IzzyOnDroid)…")
                repro += izzyRepro(apk.fileSha256)
            }
        }

        // ---- Transparency log
        val log = if (opt.online) {
            tlog.check(apk.fileSha256, pkg, apk.versionCode, opt.googleLogBundles, progress)
        } else LogCheckResult(CheckStatus.UNKNOWN, "Đang tắt tra cứu trực tuyến.")

        // Kiểm tra tương đương khi không có trong log Google: log công khai Sigstore Rekor.
        val rekor = when {
            !opt.online -> LogCheckResult(CheckStatus.UNKNOWN, "Đang tắt tra cứu trực tuyến.")
            !opt.checkRekor -> LogCheckResult(CheckStatus.NA, "Đã tắt tra Sigstore Rekor.")
            log.status == CheckStatus.PASS || log.status == CheckStatus.FAIL -> LogCheckResult(CheckStatus.NA, "Không cần: đã có kết quả từ log Google.")
            else -> RekorClient.check(apk.fileSha256, progress)
        }

        // Nhật ký minh bạch cục bộ: phát hiện split-view.
        val local = LocalLog.check(localLog.load(), pkg, apk.versionCode, apk.fileSha256, signer)

        // ---- Code Transparency
        progress("Đang kiểm Code Transparency…")
        val ct = CodeTransparency.verify(
            ins.ctJws, ins.ctEntries, expectedSplitsMissing = false,
            publishedKeys = SourceParsers.parseUserFingerprints(opt.ctKeyFingerprints),
            previousKey = previous?.ctKeyFingerprint,
            apkSignerFingerprints = signer,
        )

        // ---- Khóa dùng chung
        progress("Đang tìm app khác dùng chung khóa ký…")
        val shared = SharedKeys.assess(pkg, apk.signerCerts, inspector.siblingsSignedWith(signer))

        val report = IntegrityAnalyzer.analyze(IntegrityInput(apk, sources, ct, log, repro, market, previous, shared, rekor, local))
        if (apk.signatureVerified && signer.isNotEmpty()) localLog.append(pkg, apk.versionCode, apk.fileSha256, signer)

        // Ghi nhớ khóa để lần sau so (không ghi nếu có dấu hiệu bị thay đổi).
        if (report.verdict != com.mixedsignals.checker.domain.integrity.IntegrityVerdict.TAMPERED && signer.isNotEmpty()) {
            anchors.put(AnchorRecord(pkg, signer, ct.keyFingerprint ?: previous?.ctKeyFingerprint, previous?.firstSeen ?: System.currentTimeMillis(), System.currentTimeMillis()))
        }
        return report
    }

    private fun hostOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val h = url.trim().substringAfter("://", url.trim()).substringBefore('/').substringBefore(':').lowercase()
        return h.ifBlank { null }
    }

    private fun assetLinks(domain: String, pkg: String, signer: Set<String>): SourceResult {
        val name = "Digital Asset Links ($domain)"
        return try {
            val fps = SourceParsers.assetLinksFingerprints(String(Http.get("https://$domain/.well-known/assetlinks.json")), pkg)
            when {
                fps.isEmpty() -> SourceResult(name, CheckStatus.NA, note = "file không khai báo package này")
                fps.intersect(signer).isNotEmpty() -> SourceResult(name, CheckStatus.PASS, fps, "chủ domain xác nhận khóa ký")
                else -> SourceResult(name, CheckStatus.FAIL, fps, "domain khai báo khóa KHÁC")
            }
        } catch (e: Http.NotFound) {
            SourceResult(name, CheckStatus.NA, note = "domain không có assetlinks.json")
        } catch (e: Exception) {
            SourceResult(name, CheckStatus.UNKNOWN, note = "lỗi: ${e.message}")
        }
    }

    private fun fdroidSigner(pkg: String, signer: Set<String>): SourceResult {
        val name = "F-Droid (signer-index)"
        return try {
            val idx = String(Http.cached("https://f-droid.org/repo/signer-index.json", File(cache, "fdroid-signer-index.json"), DAY))
            val fp = SourceParsers.fdroidSigner(idx, pkg)
            when {
                fp == null -> SourceResult(name, CheckStatus.NA, note = "app không có trên F-Droid", authoritative = false)
                fp in signer -> SourceResult(name, CheckStatus.PASS, setOf(fp), "khớp khóa F-Droid công bố", authoritative = false)
                // Cùng app trên store khác thường được ký bằng khóa khác (paper §6.4) nên không coi là bị sửa.
                else -> SourceResult(name, CheckStatus.NA, setOf(fp), "khác khóa F-Droid (bản từ nguồn khác?)", authoritative = false)
            }
        } catch (e: Exception) {
            SourceResult(name, CheckStatus.UNKNOWN, note = "lỗi: ${e.message}", authoritative = false)
        }
    }

    private fun fdroidRepro(pkg: String, versionCode: Long, fileSha: String): ReproResult {
        val name = "F-Droid verification"
        return try {
            val reports = SourceParsers.fdroidVerification(String(Http.get("https://verification.f-droid.org/unsigned/${pkg}_$versionCode.apk.json")))
            when {
                reports.any { it.verified && it.publishedSha256 == fileSha } -> ReproResult(name, CheckStatus.PASS, "F-Droid build lại phiên bản $versionCode và khớp đúng file này")
                reports.any { it.verified } -> ReproResult(name, CheckStatus.NA, "F-Droid tái lập được phiên bản này nhưng file của bạn khác file F-Droid phát hành")
                reports.isNotEmpty() -> ReproResult(name, CheckStatus.FAIL, "F-Droid build lại nhưng không ra file giống hệt")
                else -> ReproResult(name, CheckStatus.NA, "chưa có kết quả")
            }
        } catch (e: Http.NotFound) {
            ReproResult(name, CheckStatus.NA, "không có báo cáo cho phiên bản này")
        } catch (e: Exception) {
            ReproResult(name, CheckStatus.UNKNOWN, "lỗi: ${e.message}")
        }
    }

    private fun izzyRepro(fileSha: String): ReproResult {
        val name = "IzzyOnDroid rbtlog"
        return try {
            val idx = String(Http.cached("https://codeberg.org/IzzyOnDroid/rbtlog/raw/branch/izzy/log/index.json", File(cache, "izzy-rbtlog-index.json"), DAY, 60_000))
            val recs = SourceParsers.izzyLookup(idx, fileSha)
            when {
                recs.any { it.reproducible == true } -> ReproResult(name, CheckStatus.PASS, "file đã được build lại từ mã nguồn và khớp từng byte (${recs.first().repository ?: recs.first().appId})")
                recs.any { it.reproducible == false } -> ReproResult(name, CheckStatus.FAIL, "build lại từ mã nguồn nhưng không ra file giống hệt")
                recs.isNotEmpty() -> ReproResult(name, CheckStatus.NA, "đã ghi nhận file nhưng chưa có kết quả build")
                else -> ReproResult(name, CheckStatus.NA, "không có bản ghi cho file này")
            }
        } catch (e: Exception) {
            ReproResult(name, CheckStatus.UNKNOWN, "lỗi: ${e.message}")
        }
    }

    companion object {
        private const val DAY = 24L * 60 * 60 * 1000
    }
}

/** Lưu khóa ký và khóa Code Transparency đã thấy cho mỗi package (tin ở lần đầu). */
class AnchorStore(private val file: File) {
    @Synchronized
    fun get(pkg: String): AnchorRecord? = load()[pkg]

    @Synchronized
    fun put(r: AnchorRecord) {
        val all = load().toMutableMap()
        all[r.packageName] = r
        val root = JSONObject()
        for ((k, v) in all) root.put(k, JSONObject().apply {
            put("signers", JSONArray(v.signerFingerprints.toList()))
            put("ct", v.ctKeyFingerprint)
            put("first", v.firstSeen)
            put("last", v.lastSeen)
        })
        file.writeText(root.toString())
    }

    @Synchronized
    fun clear() { file.delete() }

    private fun load(): Map<String, AnchorRecord> {
        if (!file.exists()) return emptyMap()
        val root = runCatching { JSONObject(file.readText()) }.getOrNull() ?: return emptyMap()
        return root.keys().asSequence().associateWith { k ->
            val o = root.getJSONObject(k)
            val arr = o.getJSONArray("signers")
            AnchorRecord(
                k, (0 until arr.length()).map { arr.getString(it) }.toSet(),
                if (o.isNull("ct")) null else o.optString("ct").ifBlank { null },
                o.optLong("first"), o.optLong("last"),
            )
        }
    }
}
