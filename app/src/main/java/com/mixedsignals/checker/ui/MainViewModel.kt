package com.mixedsignals.checker.ui

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.mixedsignals.checker.data.PackageScanner
import com.mixedsignals.checker.data.PlayStoreSource
import com.mixedsignals.checker.data.Storage
import com.mixedsignals.checker.domain.Analyzer
import com.mixedsignals.checker.domain.DeviceStats
import com.mixedsignals.checker.domain.MarkdownReport
import com.mixedsignals.checker.domain.StatsSection
import com.mixedsignals.checker.domain.VolatilityChecks
import com.mixedsignals.checker.domain.model.AppReport
import com.mixedsignals.checker.domain.model.MarketSignals
import com.mixedsignals.checker.domain.model.PackageHistory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface Screen {
    data object Home : Screen
    data object AppList : Screen
    data class Detail(val packageName: String, val fromFile: Boolean = false) : Screen
    data object Glossary : Screen
    data object IntegrityPicker : Screen
    data object IntegritySetup : Screen
    data object IntegrityResult : Screen
}

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val scanner = PackageScanner(app)
    private val storage = Storage(app)

    var reports by mutableStateOf<List<AppReport>>(emptyList()); private set
    var stats by mutableStateOf<List<StatsSection>>(emptyList()); private set
    var fileReport by mutableStateOf<AppReport?>(null); private set
    var busy by mutableStateOf(false); private set
    var progress by mutableStateOf(""); private set
    var message by mutableStateOf<String?>(null)
    var includeSystem by mutableStateOf(false)
    var lastScanAt by mutableStateOf<Long?>(null); private set

    private var histories: Map<String, PackageHistory> = emptyMap()
    private var market: Map<String, MarketSignals> = emptyMap()
    private var bulkJob: Job? = null

    val backStack = mutableStateListOf<Screen>(Screen.Home)
    val screen: Screen get() = backStack.last()

    fun navigate(s: Screen) { backStack.add(s) }
    fun back(): Boolean = if (backStack.size > 1) { backStack.removeAt(backStack.lastIndex); true } else false

    init {
        viewModelScope.launch(Dispatchers.IO) {
            histories = storage.loadHistory()
            market = storage.loadMarket()
        }
    }

    val trackedScans: Int get() = histories.values.maxOfOrNull { it.scanCount } ?: 0

    fun reportFor(s: Screen.Detail): AppReport? =
        if (s.fromFile) fileReport else reports.firstOrNull { it.signals.packageName == s.packageName }

    fun scan() {
        if (busy) return
        busy = true
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val signals = scanner.scanInstalled(includeSystem, market) { d, t -> progress = "Đang đọc $d/$t app…" }
                    val newHist = histories.toMutableMap()
                    val out = signals.map { s ->
                        val h = VolatilityChecks.updatedHistory(s, newHist[s.packageName])
                        newHist[s.packageName] = h
                        Analyzer.analyze(s, h)
                    }
                    storage.saveHistory(newHist)
                    histories = newHist
                    reports = out.sortedBy { it.score }
                    stats = DeviceStats.compute(reports, histories)
                }
                lastScanAt = System.currentTimeMillis()
                message = "Đã quét ${reports.size} app."
            } catch (e: Exception) {
                message = "Lỗi khi quét: ${e.message}"
            } finally {
                busy = false
                progress = ""
            }
        }
    }

    fun analyzeFile(uri: Uri) {
        if (busy) return
        busy = true
        progress = "Đang đọc file APK…"
        viewModelScope.launch {
            try {
                val r = withContext(Dispatchers.IO) { Analyzer.analyze(scanner.scanApkFile(uri, market), null) }
                fileReport = r
                navigate(Screen.Detail(r.signals.packageName, fromFile = true))
            } catch (e: Exception) {
                message = "Không phân tích được file: ${e.message}"
            } finally {
                busy = false
                progress = ""
            }
        }
    }

    /** Cập nhật metadata store cho một package rồi phân tích lại app đó. */
    private fun applyMarket(pkg: String, m: MarketSignals) {
        market = market + (pkg to m)
        storage.saveMarket(market)
        fileReport?.takeIf { it.signals.packageName == pkg }?.let { r ->
            fileReport = Analyzer.analyze(r.signals.copy(market = m), null)
        }
        val idx = reports.indexOfFirst { it.signals.packageName == pkg }
        if (idx >= 0) {
            val s = reports[idx].signals.copy(market = m, scannedAt = m.fetchedAt.takeIf { it > 0 } ?: System.currentTimeMillis())
            val h = VolatilityChecks.updatedHistory(s, histories[pkg], countAsScan = false)
            histories = histories + (pkg to h)
            storage.saveHistory(histories)
            reports = reports.toMutableList().also { it[idx] = Analyzer.analyze(s, h) }
            stats = DeviceStats.compute(reports, histories)
        }
    }

    fun fetchPlay(pkg: String) {
        if (busy) return
        busy = true
        progress = "Đang tra cứu Google Play…"
        viewModelScope.launch {
            try {
                val m = withContext(Dispatchers.IO) { PlayStoreSource.fetch(pkg) }
                withContext(Dispatchers.IO) { applyMarket(pkg, m) }
                message = "Đã cập nhật metadata từ Google Play."
            } catch (e: PlayStoreSource.NotFound) {
                message = e.message
            } catch (e: Exception) {
                message = "Tra cứu thất bại: ${e.message}"
            } finally {
                busy = false
                progress = ""
            }
        }
    }

    /** Tra cứu Google Play cho mọi app không phải app hệ thống, nghỉ 1,5 giây giữa các lần để tránh gửi quá dày. */
    fun fetchPlayAll() {
        if (busy) return
        val targets = reports.filter { !it.signals.isSystemApp }.map { it.signals.packageName }
        busy = true
        bulkJob = viewModelScope.launch {
            var ok = 0
            var missing = 0
            try {
                for ((i, pkg) in targets.withIndex()) {
                    progress = "Tra cứu Google Play ${i + 1}/${targets.size}: $pkg"
                    try {
                        val m = withContext(Dispatchers.IO) { PlayStoreSource.fetch(pkg) }
                        withContext(Dispatchers.IO) { applyMarket(pkg, m) }
                        ok++
                    } catch (e: PlayStoreSource.NotFound) {
                        missing++
                    } catch (e: Exception) {
                        missing++
                    }
                    delay(1500)
                }
                message = "Tra cứu xong: $ok app có trên Google Play, $missing app không tìm thấy."
            } finally {
                busy = false
                progress = ""
            }
        }
    }

    fun cancelBulk() { bulkJob?.cancel() }

    fun saveManual(pkg: String, m: MarketSignals) {
        viewModelScope.launch(Dispatchers.IO) { applyMarket(pkg, m.copy(source = "manual", fetchedAt = System.currentTimeMillis())) }
    }

    fun exportMarkdown(uri: Uri) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val text = MarkdownReport.build(reports, stats, System.currentTimeMillis())
                    getApplication<Application>().contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
                }
                message = "Đã lưu báo cáo."
            } catch (e: Exception) {
                message = "Không lưu được: ${e.message}"
            }
        }
    }

    fun clearData() {
        viewModelScope.launch(Dispatchers.IO) {
            storage.clearAll()
            histories = emptyMap()
            market = emptyMap()
            reports = emptyList()
            stats = emptyList()
            lastScanAt = null
            message = "Đã xóa lịch sử và metadata."
        }
    }
}
