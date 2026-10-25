package com.mixedsignals.checker.domain.integrity

import com.mixedsignals.checker.domain.model.CertInfo
import com.mixedsignals.checker.domain.model.MarketSignals

/**
 * Mô hình cho phần kiểm tra toàn vẹn APK (supply-chain integrity & binary transparency).
 * Thuần Kotlin để kiểm thử trên JVM.
 */

/** Trạng thái của một kiểm tra (4 trạng thái đã thống nhất). */
enum class CheckStatus(val icon: String, val label: String) {
    PASS("✅", "Đạt"),
    FAIL("❌", "Không đạt"),
    NA("⚪", "Không có dữ liệu / không áp dụng"),
    UNKNOWN("⚠️", "Chưa kiểm được"),
}

/** Kết luận cuối cùng (5 mức đã thống nhất). */
enum class IntegrityVerdict(val icon: String, val label: String, val explain: String) {
    VERIFIED(
        "🛡️", "Toàn vẹn",
        "Chữ ký hợp lệ, khóa ký khớp nguồn công bố và có bằng chứng độc lập (transparency log, reproducible build, " +
            "Code Transparency đã neo khóa, hoặc nhiều nguồn công bố khớp nhau).",
    ),
    LOW_RISK(
        "🟢", "Rủi ro thấp",
        "Chữ ký hợp lệ và khớp một nguồn công bố, hoặc được phân phối bởi store có kiểm duyệt; chưa có bằng chứng độc lập.",
    ),
    HIGH_RISK(
        "🟠", "Rủi ro cao",
        "Chữ ký hợp lệ nhưng có dấu hiệu đáng lo: khóa debug/khóa test, nghi mạo danh, bật chế độ debug, " +
            "hoặc thiếu nhiều thông tin của một app uy tín cơ bản.",
    ),
    NO_DATA(
        "⚪", "Chưa có dữ liệu",
        "Chữ ký hợp lệ nhưng không tìm thấy nguồn nào để đối chiếu danh tính.",
    ),
    TAMPERED(
        "❌", "Có dấu hiệu bị thay đổi",
        "Chữ ký hỏng, khóa ký khác nguồn công bố, hash không khớp bản ghi đã công bố, hoặc khóa bị thay mà không có lineage.",
    ),
}

const val DISCLAIMER =
    "Kết quả cho biết APK có KHỚP với những gì developer và các bên thứ ba đã công bố hay không. " +
        "Tick xanh KHÔNG có nghĩa app an toàn: một app toàn vẹn vẫn có thể thu thập dữ liệu hoặc có hành vi xấu. " +
        "Hãy cân nhắc các quyền app xin khi cài và chỉ cài app từ nguồn bạn tin cậy."

/** Một mục kiểm tra hiển thị cho người dùng. */
data class CheckResult(
    val id: String,
    val title: String,
    val status: CheckStatus,
    val summary: String,
    val details: List<String> = emptyList(),
)

/** Kết quả đối chiếu khóa ký với một nguồn công bố. */
data class SourceResult(
    val source: String,
    val status: CheckStatus,
    /** Fingerprint SHA-256 (chữ thường, không dấu ':') mà nguồn này công bố cho package. */
    val publishedFingerprints: Set<String> = emptySet(),
    val note: String = "",
    /** Nguồn chính thức của developer: không khớp nghĩa là dấu hiệu bị thay đổi. */
    val authoritative: Boolean = true,
    /** false với lịch sử trên máy (chỉ là tin ở lần đầu, không phải nguồn công bố). */
    val publication: Boolean = true,
)

/** Kết quả kiểm Code Transparency. */
data class CodeTransparencyResult(
    val status: CheckStatus,
    val summary: String,
    /** Fingerprint SHA-256 chứng chỉ khóa Code Transparency, nếu đọc được. */
    val keyFingerprint: String? = null,
    /** Khóa đã được neo (khớp nguồn công bố hoặc lần trước). */
    val keyAnchored: Boolean = false,
    val checkedFiles: Int = 0,
    val missingFiles: Int = 0,
    val modifiedFiles: List<String> = emptyList(),
)

/** Thành phần app khai báo cần quyền đặc biệt (service/receiver). */
data class ProtectedComponent(val name: String, val permission: String)

/** Mọi bằng chứng thu được về một APK. */
data class ApkEvidence(
    val fileName: String,
    val fileSha256: String,
    val fileSize: Long,
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val minSdk: Int?,
    val targetSdk: Int?,
    val debuggable: Boolean,
    val usesCleartextTraffic: Boolean,
    val requestedPermissions: List<String>,
    val protectedComponents: List<ProtectedComponent>,
    // Chữ ký
    val signatureVerified: Boolean,
    val signatureErrors: List<String>,
    val schemes: Set<Int>,
    val signerCerts: List<CertInfo>,
    val lineageCerts: List<CertInfo>,
    val sourceStampPresent: Boolean,
    val sourceStampVerified: Boolean,
    /** true nếu là app đã cài (không phải file rời). */
    val installed: Boolean = false,
    val installer: String? = null,
    /** Quyền Android tự thêm vì tương thích (developer không khai báo), ví dụ ACCESS_LOCAL_NETWORK từ INTERNET. */
    val implicitPermissions: Set<String> = emptySet(),
) {
    val signerFingerprints: Set<String> get() = signerCerts.map { it.sha256 }.toSet()
    val lineageFingerprints: Set<String> get() = lineageCerts.map { it.sha256 }.toSet()
}

/** Kết quả tra transparency log của Google. */
data class LogCheckResult(val status: CheckStatus, val summary: String, val details: List<String> = emptyList())

/** Kết quả tra reproducible build. */
data class ReproResult(val source: String, val status: CheckStatus, val summary: String)

/** Lần kiểm trước của cùng package (neo khóa theo kiểu tin ở lần đầu). */
data class AnchorRecord(
    val packageName: String,
    val signerFingerprints: Set<String>,
    val ctKeyFingerprint: String?,
    val firstSeen: Long,
    val lastSeen: Long,
)

/** Toàn bộ đầu vào cho bộ phân tích. */
data class IntegrityInput(
    val apk: ApkEvidence,
    val sources: List<SourceResult>,
    val codeTransparency: CodeTransparencyResult,
    val googleLog: LogCheckResult,
    val repro: List<ReproResult>,
    val market: MarketSignals?,
    val previous: AnchorRecord?,
    val sharedKey: SharedKeyResult = SharedKeyResult.NONE,
    /** Kiểm tra tương đương khi không có trong log Google: log công khai Sigstore Rekor. */
    val rekor: LogCheckResult = LogCheckResult(CheckStatus.NA, "Không tra Sigstore Rekor."),
    /** Nhật ký minh bạch cục bộ: phát hiện split-view (cùng phiên bản, cùng khóa, khác nội dung). */
    val localLog: LogCheckResult = LogCheckResult(CheckStatus.NA, "Chưa có nhật ký cục bộ."),
)

/** Một mục trong danh sách “app uy tín cơ bản cần có”. */
data class BaselineItem(val group: String, val title: String, val present: Boolean?, val hint: String)

/** Báo cáo cuối cùng. */
data class IntegrityReport(
    val input: IntegrityInput,
    val verdict: IntegrityVerdict,
    val verdictReasons: List<String>,
    val checks: List<CheckResult>,
    val baseline: List<BaselineItem>,
    val permissions: PermissionAssessment,
    val impersonation: ImpersonationResult,
    val score: IntegrityScore,
) {
    val missingBaseline: List<BaselineItem> get() = baseline.filter { it.present == false }
}
