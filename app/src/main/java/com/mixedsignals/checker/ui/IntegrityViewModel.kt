package com.mixedsignals.checker.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.mixedsignals.checker.data.integrity.ApkBundle
import com.mixedsignals.checker.data.integrity.IntegrityOptions
import com.mixedsignals.checker.data.integrity.IntegrityService
import com.mixedsignals.checker.domain.integrity.IntegrityReport
import com.mixedsignals.checker.domain.integrity.KeySibling
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Trạng thái cho phần kiểm tra toàn vẹn APK. */
class IntegrityViewModel(app: Application) : AndroidViewModel(app) {
    private val service = IntegrityService(app)

    var bundle by mutableStateOf<ApkBundle?>(null); private set
    var options by mutableStateOf(IntegrityOptions())
    var report by mutableStateOf<IntegrityReport?>(null); private set
    var busy by mutableStateOf(false); private set
    var progress by mutableStateOf(""); private set
    var error by mutableStateOf<String?>(null)
    var installed by mutableStateOf<List<KeySibling>>(emptyList()); private set
    var includeSystem by mutableStateOf(false)

    private fun displayName(uri: Uri): String = runCatching {
        getApplication<Application>().contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull() ?: "file.apk"

    fun pickFile(uri: Uri, onReady: () -> Unit) = prepare(onReady) { service.prepareFromUri(uri, displayName(uri)) }

    fun pickInstalled(pkg: String, onReady: () -> Unit) = prepare(onReady) { service.prepareInstalled(pkg) }

    private fun prepare(onReady: () -> Unit, block: () -> ApkBundle) {
        if (busy) return
        busy = true
        progress = "Đang chuẩn bị file…"
        report = null
        viewModelScope.launch {
            try {
                bundle = withContext(Dispatchers.IO) { block() }
                // Giữ fingerprint/website người dùng đã nhập cho lần trước chỉ khi kiểm cùng package là không cần thiết: làm mới.
                options = IntegrityOptions(online = options.online, checkGooglePlay = options.checkGooglePlay, checkIzzy = options.checkIzzy, googleLogBundles = options.googleLogBundles)
                onReady()
            } catch (e: Exception) {
                error = "Không đọc được: ${e.message}"
            } finally {
                busy = false
                progress = ""
            }
        }
    }

    fun loadInstalled() {
        viewModelScope.launch {
            installed = withContext(Dispatchers.IO) { service.installedApps(includeSystem) }
        }
    }

    fun run(onDone: () -> Unit) {
        val b = bundle ?: return
        if (busy) return
        busy = true
        viewModelScope.launch {
            try {
                report = withContext(Dispatchers.IO) { service.run(b, options) { progress = it } }
                onDone()
            } catch (e: Exception) {
                error = "Kiểm tra thất bại: ${e.message}"
            } finally {
                busy = false
                progress = ""
            }
        }
    }
}
