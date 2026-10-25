package com.mixedsignals.checker.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.Build
import com.mixedsignals.checker.domain.model.AppSignals
import com.mixedsignals.checker.domain.model.CertInfo
import com.mixedsignals.checker.domain.model.MarketSignals
import java.io.File

/** Thu thập tín hiệu attribution từ app đã cài và từ file .apk rời. */
class PackageScanner(private val context: Context) {
    private val pm: PackageManager = context.packageManager

    @Suppress("DEPRECATION")
    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_SIGNING_CERTIFICATES
        return if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getInstalledPackages(flags)
        }
    }

    /**
     * Quét các app đã cài.
     * @param includeSystem có tính app hệ thống (thường được ký bằng khóa của hãng) hay không.
     */
    fun scanInstalled(
        includeSystem: Boolean,
        market: Map<String, MarketSignals>,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> },
    ): List<AppSignals> {
        val now = System.currentTimeMillis()
        val pkgs = installedPackages().filter { p ->
            val ai = p.applicationInfo ?: return@filter false
            p.packageName != context.packageName &&
                (includeSystem || (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                    (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0)
        }
        return pkgs.mapIndexed { i, p ->
            onProgress(i + 1, pkgs.size)
            fromInstalled(p, market[p.packageName], now)
        }
    }

    private fun fromInstalled(p: PackageInfo, market: MarketSignals?, now: Long): AppSignals {
        val ai = p.applicationInfo!!
        val si = p.signingInfo
        val multi = si?.hasMultipleSigners() == true
        val current = si?.apkContentsSigners.toCertInfos()
        val history = if (si != null && !multi) si.signingCertificateHistory.toCertInfos() else emptyList()
        val schemes = runCatching { ApkSignatureReader.read(File(ai.sourceDir)).schemes }.getOrDefault(emptySet())
        return AppSignals(
            packageName = p.packageName,
            manifestLabel = ai.loadLabel(pm).toString(),
            versionName = p.versionName,
            versionCode = p.longVersionCode,
            installer = installerOf(p.packageName),
            isSystemApp = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            fromFile = false,
            schemes = schemes,
            currentCerts = current,
            certHistory = history,
            hasMultipleSigners = multi,
            market = market,
            scannedAt = now,
        )
    }

    @Suppress("DEPRECATION")
    private fun installerOf(pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            pm.getInstallerPackageName(pkg)
        }
    }.getOrNull()

    private fun Array<Signature>?.toCertInfos(): List<CertInfo> =
        this?.mapNotNull { CertParser.parse(it.toByteArray()) }.orEmpty()

    /** Phân tích một file .apk do người dùng chọn (chép vào cache trước khi đọc). */
    fun scanApkFile(uri: Uri, market: Map<String, MarketSignals>): AppSignals {
        val tmp = File(context.cacheDir, "picked.apk")
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Không mở được file" }
            tmp.outputStream().use { input.copyTo(it) }
        }
        val sig = ApkSignatureReader.read(tmp)

        @Suppress("DEPRECATION")
        val p = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(tmp.path, PackageManager.PackageInfoFlags.of(0))
        } else {
            pm.getPackageArchiveInfo(tmp.path, 0)
        }
        val ai = p?.applicationInfo?.apply {
            sourceDir = tmp.path
            publicSourceDir = tmp.path
        }
        val pkg = p?.packageName ?: "(không đọc được manifest)"
        return AppSignals(
            packageName = pkg,
            manifestLabel = ai?.loadLabel(pm)?.toString() ?: pkg,
            versionName = p?.versionName,
            versionCode = p?.longVersionCode ?: 0,
            installer = null,
            isSystemApp = false,
            fromFile = true,
            schemes = sig.schemes,
            currentCerts = sig.signerCerts.map { CertParser.fromX509(it) },
            // Lineage v3 nằm trong thuộc tính bổ sung của khối v3; bản này chưa đọc cho file rời.
            certHistory = emptyList(),
            hasMultipleSigners = sig.signerCount > 1,
            market = market[pkg],
        )
    }
}
