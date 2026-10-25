package com.mixedsignals.checker.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mixedsignals.checker.domain.AvailabilityChecks
import com.mixedsignals.checker.domain.CertClassifier
import com.mixedsignals.checker.domain.model.AppReport
import com.mixedsignals.checker.domain.model.CERT_RDN_KEYS
import com.mixedsignals.checker.domain.model.CertInfo
import com.mixedsignals.checker.domain.model.ConfidenceLevel
import com.mixedsignals.checker.domain.model.Finding
import com.mixedsignals.checker.domain.model.MarketField
import com.mixedsignals.checker.domain.model.MarketSignals
import com.mixedsignals.checker.domain.model.RDN_LABELS

private val INSTALLERS = mapOf(
    "com.android.vending" to "Google Play",
    "com.huawei.appmarket" to "Huawei AppGallery",
    "com.sec.android.app.samsungapps" to "Samsung Galaxy Store",
    "com.xiaomi.market" to "Xiaomi GetApps",
    "com.amazon.venezia" to "Amazon Appstore",
    "com.tencent.android.qqdownloader" to "Tencent MyApp",
    "com.baidu.appsearch" to "Baidu",
    "org.fdroid.fdroid" to "F-Droid",
    "com.google.android.packageinstaller" to "Cài từ file (sideload)",
    "com.android.packageinstaller" to "Cài từ file (sideload)",
    "com.android.shell" to "Cài qua adb",
)

fun installerName(pkg: String?): String = when (pkg) {
    null -> "Không rõ"
    else -> INSTALLERS[pkg]?.let { "$it ($pkg)" } ?: pkg
}

@Composable
fun ScoreDot(color: Color) {
    Box(Modifier.size(12.dp).clip(CircleShape).background(color))
}

@Composable
fun ScoreBadge(score: Int, level: ConfidenceLevel) {
    Box(
        Modifier.clip(RoundedCornerShape(8.dp)).background(levelColor(level)).padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
        Text("$score", color = Color.White, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun AppListScreen(vm: MainViewModel) {
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf<ConfidenceLevel?>(null) }
    val list = vm.reports.filter { r ->
        (filter == null || r.level == filter) &&
            (
                query.isBlank() || r.signals.manifestLabel.contains(query, true) ||
                    r.signals.packageName.contains(query, true) ||
                    r.findings.any { it.title.contains(query, true) || it.id.contains(query, true) }
                )
    }
    Column {
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Tìm theo tên, package hoặc phát hiện") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
        LazyRow(contentPadding = PaddingValues(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            item { FilterChip(selected = filter == null, onClick = { filter = null }, label = { Text("Tất cả (${vm.reports.size})") }) }
            items(ConfidenceLevel.entries) { l ->
                FilterChip(
                    selected = filter == l, onClick = { filter = l },
                    label = { Text("${l.label} (${vm.reports.count { it.level == l }})") },
                )
            }
        }
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(list, key = { it.signals.packageName }) { r ->
                Card(Modifier.fillMaxWidth().clickable { vm.navigate(Screen.Detail(r.signals.packageName)) }) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(r.signals.manifestLabel, fontWeight = FontWeight.SemiBold)
                            Text(r.signals.packageName, style = MaterialTheme.typography.bodySmall)
                            val parts = buildList {
                                if (r.highCount > 0) add("${r.highCount} mức cao")
                                if (r.mediumCount > 0) add("${r.mediumCount} trung bình")
                                if (r.changes.isNotEmpty()) add("${r.changes.size} thay đổi")
                            }
                            if (parts.isNotEmpty()) Text(parts.joinToString(" · "), style = MaterialTheme.typography.labelSmall)
                        }
                        ScoreBadge(r.score, r.level)
                    }
                }
            }
        }
    }
}

@Composable
fun DetailScreen(vm: MainViewModel, screen: Screen.Detail) {
    val r = vm.reportFor(screen)
    if (r == null) {
        Text("Không tìm thấy dữ liệu.", Modifier.padding(16.dp))
        return
    }
    var editing by remember { mutableStateOf(false) }
    val s = r.signals
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Card {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(s.manifestLabel, style = MaterialTheme.typography.titleLarge)
                    Text(s.packageName, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    Text("Phiên bản ${s.versionName ?: "?"} (${s.versionCode})", style = MaterialTheme.typography.bodySmall)
                    Text(
                        when {
                            s.fromFile -> "Nguồn: file APK chưa cài"
                            s.isSystemApp && s.installer == null -> "Cài sẵn trong hệ thống (firmware)"
                            else -> "Trình cài đặt: ${installerName(s.installer)}"
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(r.level.label, color = levelColor(r.level), fontWeight = FontWeight.SemiBold)
                }
                ScoreBadge(r.score, r.level)
            }
        }

        SectionTitle("Phát hiện (${r.findings.size})")
        r.findings.forEach { FindingCard(it) }

        SectionTitle("Chứng chỉ ký")
        Text(
            "Scheme: " + s.schemes.sorted().joinToString { AvailabilityChecks.schemeName(it) }.ifEmpty { "không rõ" },
            style = MaterialTheme.typography.bodyMedium,
        )
        s.currentCerts.forEach { CertCard(it) }
        if (s.certHistory.size > 1) {
            Text("Lịch sử xoay khóa (cũ → mới):", style = MaterialTheme.typography.bodyMedium)
            s.certHistory.forEach { Text("• ${it.sha256.take(24)}… ${it.subjectString}", style = MaterialTheme.typography.bodySmall) }
        }

        SectionTitle("Metadata trên store")
        MarketCard(s.market)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { vm.fetchPlay(s.packageName) }, enabled = !vm.busy) { Text("Tra cứu Google Play") }
            OutlinedButton(onClick = { editing = true }) { Text("Sửa thủ công") }
        }

        if (!s.fromFile) {
            SectionTitle("Lịch sử thay đổi")
            val h = r.history
            Text(
                if (h.isEmpty()) "Chưa có lịch sử."
                else "Mốc đầu: ${fmtDate(h.first().scannedAt)} · ${h.size} bản ghi khác nhau",
                style = MaterialTheme.typography.bodySmall,
            )
            if (r.changes.isEmpty()) {
                Text("Chưa ghi nhận thay đổi nào. Quét lại sau một thời gian để đo độ biến động.", style = MaterialTheme.typography.bodySmall)
            } else {
                r.changes.forEach { c ->
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Column(Modifier.padding(10.dp).fillMaxWidth()) {
                            Text("${fmtDate(c.at)} · ${c.signal}", style = MaterialTheme.typography.labelMedium)
                            Text("\"${c.from}\" → \"${c.to}\"", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
    if (editing) {
        MarketDialog(
            initial = s.market ?: MarketSignals(),
            onDismiss = { editing = false },
            onSave = { vm.saveManual(s.packageName, it); editing = false },
        )
    }
}

@Composable
private fun SectionTitle(t: String) {
    Text(t, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 4.dp))
}

@Composable
private fun FindingCard(f: Finding) {
    Card {
        Row(Modifier.padding(12.dp)) {
            Box(Modifier.width(4.dp).height(48.dp).background(severityColor(f.severity)))
            Column(Modifier.padding(start = 10.dp)) {
                Text(
                    "${f.severity.label} · ${f.group.label} · paper ${f.paperRef}",
                    style = MaterialTheme.typography.labelSmall, color = severityColor(f.severity),
                )
                Text(f.title, fontWeight = FontWeight.SemiBold)
                Text(f.detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun CertCard(c: CertInfo) {
    Card {
        Column(Modifier.padding(12.dp)) {
            Text("SHA-256: ${c.sha256}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            Text(
                "Loại: ${CertClassifier.classify(c).label} · ${if (c.selfSigned) "tự ký" else "do CA khác cấp"}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                "${c.keyAlg} ${c.keySizeBits ?: "?"} bit · ${c.sigAlg} · hiệu lực ${fmtDate(c.notBefore).take(10)} → ${fmtDate(c.notAfter).take(10)}",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(6.dp))
            HorizontalDivider()
            for (k in CERT_RDN_KEYS) {
                val v = c.subject[k]
                Row(Modifier.padding(vertical = 2.dp)) {
                    Text("$k (${RDN_LABELS[k]})", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    Text(
                        v ?: "— thiếu", Modifier.weight(1.3f), style = MaterialTheme.typography.bodySmall,
                        color = if (v == null) MissingColor else Color.Unspecified,
                        fontWeight = if (v == null) FontWeight.SemiBold else FontWeight.Normal,
                    )
                }
            }
            c.subject.filterKeys { it !in CERT_RDN_KEYS }.forEach { (k, v) ->
                Text("$k: $v", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun MarketCard(m: MarketSignals?) {
    Card {
        Column(Modifier.padding(12.dp)) {
            if (m == null || m.isEmpty) {
                Text("Chưa có dữ liệu. Tra cứu Google Play hoặc nhập tay.", style = MaterialTheme.typography.bodySmall)
                return@Column
            }
            Text(
                "Nguồn: ${if (m.source == "play") "Google Play" else "nhập tay"}" +
                    (if (m.fetchedAt > 0) " · ${fmtDate(m.fetchedAt)}" else ""),
                style = MaterialTheme.typography.labelSmall,
            )
            for (f in MarketField.entries) {
                val v = m.get(f)
                Row(Modifier.padding(vertical = 2.dp)) {
                    Text(f.label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    Text(
                        v ?: "— thiếu", Modifier.weight(1.3f), style = MaterialTheme.typography.bodySmall,
                        color = if (v == null) MissingColor else Color.Unspecified,
                    )
                }
            }
        }
    }
}

@Composable
private fun MarketDialog(initial: MarketSignals, onDismiss: () -> Unit, onSave: (MarketSignals) -> Unit) {
    val values = remember { mutableStateMapOf<MarketField, String>().apply { MarketField.entries.forEach { put(it, initial.get(it).orEmpty()) } } }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Metadata trên store") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                MarketField.entries.forEach { f ->
                    OutlinedTextField(
                        value = values[f].orEmpty(), onValueChange = { values[f] = it },
                        label = { Text(f.label) }, modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                fun v(f: MarketField) = values[f]?.trim()?.ifEmpty { null }
                onSave(
                    MarketSignals(
                        appName = v(MarketField.APP_NAME),
                        developerName = v(MarketField.DEVELOPER_NAME),
                        website = v(MarketField.WEBSITE),
                        email = v(MarketField.EMAIL),
                        address = v(MarketField.ADDRESS),
                        privacyPolicyUrl = v(MarketField.PRIVACY_POLICY),
                    ),
                )
            }) { Text("Lưu") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
    )
}

val GLOSSARY = listOf(
    "Attribution (quy danh tác giả)" to "Xác định công ty nào đứng sau một app và chịu trách nhiệm về nó (paper, Định nghĩa 1).",
    "Tín hiệu attribution" to "Dữ liệu công khai gợi ý tác giả: package name, tên app, thông tin developer trên store, chứng chỉ ký.",
    "Độ sẵn có (availability)" to "Tín hiệu có được cung cấp hay không. Paper đo tỷ lệ app thiếu từng tín hiệu (Bảng 4).",
    "Độ biến động (volatility)" to "Tín hiệu có thay đổi theo thời gian hay không. Paper so hai đợt crawl cách nhau nhiều tháng (Bảng 5).",
    "Chứng chỉ ký (signing certificate)" to "Chứng chỉ X.509 gắn với khóa dùng để ký APK; Android dùng nó để đảm bảo bản cập nhật đến từ cùng người ký.",
    "Chứng chỉ tự ký (self-signed)" to "Subject trùng Issuer: chủ chứng chỉ tự tạo và tự điền thông tin, không có bên nào xác minh.",
    "Subject / RDN" to "Phần mô tả chủ chứng chỉ, gồm các trường (RDN): CN tên, O tổ chức, OU bộ phận, L thành phố, ST tỉnh/bang, C quốc gia.",
    "Fingerprint SHA-256" to "Mã băm của chứng chỉ, dùng làm định danh duy nhất để so sánh chứng chỉ giữa các lần quét.",
    "Signature scheme v1/v2/v3/v3.1" to "Các định dạng chữ ký APK. v1 ký từng file trong JAR; v2 ký cả file; v3 thêm xoay khóa; v3.1 nhắm theo phiên bản Android.",
    "Xoay khóa (key rotation)" to "Chữ ký v3 cho phép thay khóa ký, kèm bằng chứng (lineage) rằng khóa mới kế thừa khóa cũ.",
    "Play App Signing" to "Dịch vụ Google giữ khóa và ký app thay developer; khi đó chứng chỉ trên máy là của Google chứ không phải của tác giả.",
    "Chứng chỉ debug" to "Khóa Android SDK tự sinh khi lập trình (CN=Android Debug), không dùng để phát hành.",
    "Khóa test AOSP" to "Các khóa mẫu trong mã nguồn Android (android@android.com); private key công khai nên ai cũng ký được.",
    "Market metadata" to "Thông tin developer tự khai trên trang store: tên developer, website, email, địa chỉ, privacy policy.",
    "Điểm (0–100)" to "100 trừ trọng số các phát hiện (Cao 25, Trung bình 10, Thấp 4). Đo mức đầy đủ và ổn định của tín hiệu, không đo mức an toàn.",
)

@Composable
fun GlossaryScreen() {
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(GLOSSARY) { (term, def) ->
            Card {
                Column(Modifier.padding(12.dp)) {
                    Text(term, fontWeight = FontWeight.SemiBold)
                    Text(def, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        item {
            Text(
                "Giới hạn: app chỉ đo tín hiệu tự khai; không có ground truth để biết tác giả thật. " +
                    "Cảnh báo không có nghĩa app độc hại.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}
