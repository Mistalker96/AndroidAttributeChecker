package com.mixedsignals.checker.data

import android.content.Context
import com.mixedsignals.checker.domain.model.MarketSignals
import com.mixedsignals.checker.domain.model.PackageHistory
import com.mixedsignals.checker.domain.model.SnapshotEntry
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Lưu dữ liệu vào bộ nhớ trong của app dưới dạng JSON:
 *  - history.json: lịch sử tín hiệu từng package (để đo biến động, §5.2);
 *  - market.json: metadata store đã tra cứu / nhập tay.
 */
class Storage(context: Context) {
    private val historyFile = File(context.filesDir, "history.json")
    private val marketFile = File(context.filesDir, "market.json")

    @Synchronized
    fun loadHistory(): Map<String, PackageHistory> {
        if (!historyFile.exists()) return emptyMap()
        val root = runCatching { JSONObject(historyFile.readText()) }.getOrNull() ?: return emptyMap()
        val out = LinkedHashMap<String, PackageHistory>()
        for (pkg in root.keys()) {
            val o = root.getJSONObject(pkg)
            val arr = o.getJSONArray("entries")
            val entries = (0 until arr.length()).map { entryFrom(pkg, arr.getJSONObject(it)) }
            out[pkg] = PackageHistory(pkg, entries, o.getInt("scanCount"), o.getLong("firstSeen"), o.getLong("lastSeen"))
        }
        return out
    }

    @Synchronized
    fun saveHistory(all: Map<String, PackageHistory>) {
        val root = JSONObject()
        for ((pkg, h) in all) {
            root.put(pkg, JSONObject().apply {
                put("scanCount", h.scanCount)
                put("firstSeen", h.firstSeen)
                put("lastSeen", h.lastSeen)
                put("entries", JSONArray().apply { h.entries.forEach { put(entryTo(it)) } })
            })
        }
        writeAtomic(historyFile, root.toString())
    }

    @Synchronized
    fun loadMarket(): Map<String, MarketSignals> {
        if (!marketFile.exists()) return emptyMap()
        val root = runCatching { JSONObject(marketFile.readText()) }.getOrNull() ?: return emptyMap()
        return root.keys().asSequence().associateWith { marketFrom(root.getJSONObject(it)) }
    }

    @Synchronized
    fun saveMarket(all: Map<String, MarketSignals>) {
        val root = JSONObject()
        for ((pkg, m) in all) root.put(pkg, marketTo(m))
        writeAtomic(marketFile, root.toString())
    }

    @Synchronized
    fun clearAll() {
        historyFile.delete()
        marketFile.delete()
    }

    private fun writeAtomic(f: File, text: String) {
        val tmp = File(f.parentFile, f.name + ".tmp")
        tmp.writeText(text)
        if (!tmp.renameTo(f)) {
            f.delete()
            tmp.renameTo(f)
        }
    }

    private fun entryTo(e: SnapshotEntry) = JSONObject().apply {
        put("label", e.label)
        put("versionCode", e.versionCode)
        put("fps", JSONArray(e.fingerprints.toList()))
        put("hist", JSONArray(e.historyFingerprints.toList()))
        e.market?.let { put("market", marketTo(it)) }
        put("at", e.scannedAt)
    }

    private fun entryFrom(pkg: String, o: JSONObject) = SnapshotEntry(
        packageName = pkg,
        label = o.getString("label"),
        versionCode = o.optLong("versionCode"),
        fingerprints = o.getJSONArray("fps").strings().toSet(),
        historyFingerprints = o.optJSONArray("hist")?.strings()?.toSet().orEmpty(),
        market = o.optJSONObject("market")?.let(::marketFrom),
        scannedAt = o.getLong("at"),
    )

    private fun marketTo(m: MarketSignals) = JSONObject().apply {
        put("appName", m.appName)
        put("developerName", m.developerName)
        put("website", m.website)
        put("email", m.email)
        put("address", m.address)
        put("privacyPolicyUrl", m.privacyPolicyUrl)
        put("source", m.source)
        put("fetchedAt", m.fetchedAt)
    }

    private fun marketFrom(o: JSONObject) = MarketSignals(
        appName = o.str("appName"),
        developerName = o.str("developerName"),
        website = o.str("website"),
        email = o.str("email"),
        address = o.str("address"),
        privacyPolicyUrl = o.str("privacyPolicyUrl"),
        source = o.optString("source", "manual"),
        fetchedAt = o.optLong("fetchedAt"),
    )

    private fun JSONObject.str(k: String): String? =
        if (isNull(k)) null else optString(k).takeIf { it.isNotBlank() }

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
}
