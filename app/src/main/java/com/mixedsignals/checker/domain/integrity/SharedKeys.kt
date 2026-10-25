package com.mixedsignals.checker.domain.integrity

import com.mixedsignals.checker.domain.model.CertInfo

/**
 * Phát hiện nền tảng tạo app và khóa ký dùng chung (paper §6.3, §7.2): khi một khóa ký app của nhiều
 * developer, khóa đó nói lên nền tảng/bên ký chứ KHÔNG nói lên tác giả.
 */
data class AppBuilder(
    val name: String,
    /** Từ khóa (chữ thường) tìm trong subject chứng chỉ. Cần kiểm chứng bằng APK thật. */
    val certKeywords: List<String>,
    val packageRegex: Regex? = null,
)

/** Một app khác trên máy ký cùng khóa. */
data class KeySibling(val packageName: String, val label: String)

data class SharedKeyResult(
    val builder: AppBuilder?,
    val builderReason: String?,
    /** App khác trên máy dùng chung khóa, thuộc developer khác (khác tiền tố package). */
    val foreignSiblings: List<KeySibling>,
    /** App khác dùng chung khóa nhưng cùng tiền tố package (có thể cùng developer). */
    val ownSiblings: List<KeySibling>,
    /** false nếu không quét được danh sách app trên máy. */
    val deviceScanned: Boolean,
) {
    val detected: Boolean get() = builder != null || foreignSiblings.isNotEmpty()

    companion object {
        val NONE = SharedKeyResult(null, null, emptyList(), emptyList(), deviceScanned = false)
    }
}

object SharedKeys {
    /** Danh sách nền tảng tạo app paper nêu tên (§6.3, §7.2). */
    val BUILDERS = listOf(
        AppBuilder("Andromo", listOf("andromo"), Regex("^(com|net)\\.andromo\\.dev\\d+\\.app\\d+$")),
        AppBuilder("Appy Pie", listOf("appypie", "appy pie")),
        AppBuilder("Seattle Cloud", listOf("seattleclouds", "seattle cloud")),
        AppBuilder("Bizness Apps", listOf("bizness apps", "biznessapps")),
        AppBuilder("Mobincube", listOf("mobincube")),
        AppBuilder("AppsGeyser", listOf("appsgeyser")),
    )

    fun detectBuilder(packageName: String, certs: List<CertInfo>): Pair<AppBuilder, String>? {
        for (b in BUILDERS) {
            if (b.packageRegex?.matches(packageName) == true) {
                return b to "Package `$packageName` theo mẫu của ${b.name}."
            }
            val hit = certs.firstOrNull { c -> c.subject.values.any { v -> b.certKeywords.any { v.contains(it, ignoreCase = true) } } }
            if (hit != null) return b to "Subject chứng chỉ (${hit.subjectString}) chứa tên ${b.name}."
        }
        return null
    }

    /**
     * Các namespace thuộc cùng một hãng lớn (paper §7.2: công ty lớn phát hành dưới nhiều tên).
     * Ví dụ Google ký Chrome (com.android.chrome) và Gmail (com.google.android.gm) bằng cùng một khóa.
     */
    private val VENDOR_NAMESPACES = mapOf(
        "com.google" to "Google", "com.android" to "Google", "com.chrome" to "Google",
        "com.samsung" to "Samsung", "com.sec" to "Samsung",
        "com.microsoft" to "Microsoft", "com.skype" to "Microsoft",
        "com.huawei" to "Huawei", "com.hihonor" to "Honor",
        "com.xiaomi" to "Xiaomi", "com.miui" to "Xiaomi",
        "com.oppo" to "OPPO", "com.coloros" to "OPPO", "com.heytap" to "OPPO",
    )

    /** Hai đoạn đầu của package, dùng làm “dấu hiệu developer” thô (com.facebook.katana → com.facebook). */
    fun authorPrefix(packageName: String): String {
        val p = packageName.split('.').take(2).joinToString(".")
        return VENDOR_NAMESPACES[p] ?: p
    }

    fun assess(packageName: String, certs: List<CertInfo>, siblings: List<KeySibling>?): SharedKeyResult {
        val builder = detectBuilder(packageName, certs)
        val others = siblings.orEmpty().filter { it.packageName != packageName }
        val mine = authorPrefix(packageName)
        val (own, foreign) = others.partition { authorPrefix(it.packageName) == mine }
        return SharedKeyResult(builder?.first, builder?.second, foreign, own, deviceScanned = siblings != null)
    }
}
