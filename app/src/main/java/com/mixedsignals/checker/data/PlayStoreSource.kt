package com.mixedsignals.checker.data

import com.mixedsignals.checker.domain.model.MarketSignals
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLDecoder

/**
 * Tra cứu metadata của app trên trang Google Play (best-effort).
 * Trang Play thay đổi cấu trúc thường xuyên, nên mỗi trường được tìm bằng nhiều cách
 * và trường không tìm thấy để trống; người dùng luôn có thể sửa tay.
 */
object PlayStoreSource {

    class NotFound : Exception("App không có trên Google Play (hoặc bị giới hạn khu vực)")

    fun fetch(packageName: String): MarketSignals {
        val url = URL("https://play.google.com/store/apps/details?id=$packageName&hl=en&gl=US")
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 20_000
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AttributionChecker/1.0")
        conn.setRequestProperty("Accept-Language", "en-US,en;q=0.8")
        try {
            if (conn.responseCode == 404) throw NotFound()
            if (conn.responseCode !in 200..299) error("HTTP ${conn.responseCode}")
            val html = conn.inputStream.bufferedReader().use { it.readText() }
            return parse(html)
        } finally {
            conn.disconnect()
        }
    }

    fun parse(html: String): MarketSignals {
        val appName = Regex("<meta\\s+property=\"og:title\"\\s+content=\"([^\"]+)\"").find(html)
            ?.groupValues?.get(1)?.let(::unescape)
            ?.removeSuffix(" - Apps on Google Play")?.removeSuffix(" – Apps on Google Play")

        val developer = Regex("href=\"/store/apps/dev(?:eloper)?\\?id=[^\"]+\"[^>]*>\\s*(?:<[^>]+>\\s*)*([^<]+)<")
            .find(html)?.groupValues?.get(1)?.trim()?.let(::unescape)

        val email = Regex("mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})").find(html)
            ?.groupValues?.get(1)

        val privacy = linkNear(html, "Privacy [Pp]olicy")
        val website = linkNear(html, "Website")

        // Địa chỉ chỉ có trong khối dữ liệu JSON nhúng, dạng ["Tên", ["email"], ["địa chỉ"], "điện thoại"].
        // Chỉ dùng lớp ký tự có giới hạn độ dài (không dùng nhóm lặp) để regex chạy nhanh trên trang ~1 MB.
        val address = Regex("\\[\"[^\"\\\\]{1,200}\",\\[\"[^\"@\\\\]{1,100}@[^\"\\\\]{1,100}\"\\],\\[\"([^\"]{1,400})\"\\]")
            .find(html)?.groupValues?.get(1)
            ?.replace("\\n", ", ")?.replace("\\u0026", "&")?.replace("\\\"", "\"")

        return MarketSignals(
            appName = appName,
            developerName = developer,
            website = website,
            email = email,
            address = address,
            privacyPolicyUrl = privacy,
            source = "play",
            fetchedAt = System.currentTimeMillis(),
        )
    }

    /**
     * Tìm URL của liên kết trong mục "App support" có aria-label bắt đầu bằng [label]
     * (ví dụ aria-label="Website https://... will open in a new window or tab.").
     */
    private fun linkNear(html: String, label: String): String? {
        val p = Regex("<a[^>]+href=\"([^\"]+)\"[^>]*aria-label=\"$label [^\"]*\"")
        for (m in p.findAll(html)) {
            val href = cleanUrl(m.groupValues[1]) ?: continue
            if (href.startsWith("http")) return href
        }
        return null
    }

    private fun cleanUrl(href: String): String? {
        val h = unescape(href)
        // Liên kết ngoài trên Play đôi khi đi qua https://www.google.com/url?q=...
        if (h.contains("google.com/url?")) {
            val q = Regex("[?&]q=([^&]+)").find(h)?.groupValues?.get(1) ?: return null
            return URLDecoder.decode(q, "UTF-8")
        }
        return h
    }

    private fun unescape(s: String) = s
        .replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'")
        .replace("&lt;", "<").replace("&gt;", ">").trim()
}
