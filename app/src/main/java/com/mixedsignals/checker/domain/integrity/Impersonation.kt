package com.mixedsignals.checker.domain.integrity

import com.mixedsignals.checker.domain.text.Normalizer

/** App phổ biến hay bị giả mạo: tên hiển thị và các package chính thức. */
data class PopularApp(val name: String, val aliases: List<String>, val packages: Set<String>)

data class ImpersonationResult(
    val suspected: Boolean,
    val target: PopularApp? = null,
    val similarity: Double = 0.0,
    val reason: String = "",
)

object Impersonation {
    /**
     * Danh sách package chính thức của các app phổ biến (đặc biệt ở Việt Nam). Chỉ gồm package đã biết chắc;
     * có thể mở rộng. Không chứa fingerprint vì việc đó cần nguồn công bố của chính developer.
     */
    val POPULAR = listOf(
        PopularApp("Facebook", listOf("facebook"), setOf("com.facebook.katana", "com.facebook.lite")),
        PopularApp("Messenger", listOf("messenger"), setOf("com.facebook.orca", "com.facebook.mlite")),
        PopularApp("Instagram", listOf("instagram"), setOf("com.instagram.android", "com.instagram.lite")),
        PopularApp("WhatsApp", listOf("whatsapp"), setOf("com.whatsapp", "com.whatsapp.w4b")),
        PopularApp("Telegram", listOf("telegram"), setOf("org.telegram.messenger", "org.telegram.messenger.web")),
        PopularApp("Zalo", listOf("zalo"), setOf("com.zing.zalo")),
        PopularApp("TikTok", listOf("tiktok"), setOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill")),
        PopularApp("YouTube", listOf("youtube"), setOf("com.google.android.youtube")),
        PopularApp("Gmail", listOf("gmail"), setOf("com.google.android.gm")),
        PopularApp("Google Chrome", listOf("chrome", "google chrome"), setOf("com.android.chrome")),
        PopularApp("Signal", listOf("signal", "signal private messenger"), setOf("org.thoughtcrime.securesms")),
        PopularApp("Shopee", listOf("shopee"), setOf("com.shopee.vn")),
        PopularApp("Lazada", listOf("lazada"), setOf("com.lazada.android")),
        PopularApp("Tiki", listOf("tiki"), setOf("vn.tiki.app.tikiandroid")),
        PopularApp("Grab", listOf("grab"), setOf("com.grabtaxi.passenger")),
        PopularApp("MoMo", listOf("momo", "vi momo"), setOf("com.mservice.momotransfer")),
        PopularApp("Spotify", listOf("spotify"), setOf("com.spotify.music")),
        PopularApp("Netflix", listOf("netflix"), setOf("com.netflix.mediaclient")),
        PopularApp("Viber", listOf("viber"), setOf("com.viber.voip")),
        PopularApp("X (Twitter)", listOf("twitter", "x"), setOf("com.twitter.android")),
        PopularApp("Snapchat", listOf("snapchat"), setOf("com.snapchat.android")),
    )

    fun similarity(a: String, b: String): Double {
        val max = maxOf(a.length, b.length)
        if (max == 0) return 1.0
        return 1.0 - levenshtein(a, b).toDouble() / max
    }

    private fun levenshtein(a: String, b: String): Int {
        var prev = IntArray(b.length + 1) { it }
        var cur = IntArray(b.length + 1)
        for (i in 1..a.length) {
            cur[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = minOf(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            }
            val t = prev; prev = cur; cur = t
        }
        return prev[b.length]
    }

    /**
     * Nghi mạo danh khi tên app gần giống tên một app phổ biến (hoặc chứa nguyên tên đó như một từ)
     * nhưng package không phải package chính thức. Alias quá ngắn (như "x") chỉ khớp khi trùng hẳn.
     */
    fun detect(label: String, packageName: String): ImpersonationResult {
        val l = Normalizer.basic(label)
        if (l.isEmpty()) return ImpersonationResult(false)
        val words = l.split(' ').toSet()
        var best: Pair<PopularApp, Double>? = null
        for (app in POPULAR) {
            if (packageName in app.packages) return ImpersonationResult(false, app, 1.0, "Package chính thức của ${app.name}")
            for (alias in app.aliases) {
                val sim = when {
                    l == alias -> 1.0
                    alias.length >= 4 && (alias in words || alias.split(' ').all { it in words }) -> 0.95
                    // Tên ngắn đổi đúng 1 ký tự ("Zal0", "Grap") vẫn là mạo danh dù độ giống chỉ ~75%.
                    alias.length >= 4 && words.any { it.length == alias.length && levenshtein(it, alias) == 1 } -> 0.85
                    alias.length >= 4 -> similarity(l, alias)
                    else -> 0.0
                }
                if (sim > (best?.second ?: 0.0)) best = app to sim
            }
        }
        val b = best ?: return ImpersonationResult(false)
        return if (b.second >= 0.8) {
            ImpersonationResult(
                true, b.first, b.second,
                "Tên “$label” giống “${b.first.name}” nhưng package `$packageName` không phải package chính thức " +
                    "(${b.first.packages.joinToString()}).",
            )
        } else ImpersonationResult(false, b.first, b.second)
    }
}
