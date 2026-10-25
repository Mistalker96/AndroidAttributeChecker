package com.mixedsignals.checker.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mixedsignals.checker.domain.integrity.CheckResult
import com.mixedsignals.checker.domain.integrity.CheckStatus
import com.mixedsignals.checker.domain.integrity.DISCLAIMER
import com.mixedsignals.checker.domain.integrity.IntegrityMarkdown
import com.mixedsignals.checker.domain.integrity.IntegrityVerdict
import com.mixedsignals.checker.domain.integrity.PermissionCatalog
import com.mixedsignals.checker.domain.integrity.RiskTier
import com.mixedsignals.checker.domain.integrity.Scoring

fun verdictColor(v: IntegrityVerdict): Color = when (v) {
    IntegrityVerdict.VERIFIED -> Color(0xFF1B7F4B)
    IntegrityVerdict.LOW_RISK -> Color(0xFF2E8B57)
    IntegrityVerdict.HIGH_RISK -> Color(0xFFD97706)
    IntegrityVerdict.NO_DATA -> Color(0xFF78909C)
    IntegrityVerdict.TAMPERED -> Color(0xFFD32F2F)
}

fun tierColor(t: RiskTier): Color = when (t) {
    RiskTier.RED -> Color(0xFFD32F2F)
    RiskTier.YELLOW -> Color(0xFFE0A100)
    RiskTier.GREEN -> Color(0xFF2E7D32)
}

fun statusColor(s: CheckStatus): Color = when (s) {
    CheckStatus.PASS -> Color(0xFF2E7D32)
    CheckStatus.FAIL -> Color(0xFFD32F2F)
    CheckStatus.NA -> Color(0xFF78909C)
    CheckStatus.UNKNOWN -> Color(0xFFE08A00)
}

/** Thẻ ở màn hình chính: lối vào kiểm tra APK trước khi cài. */
@Composable
fun IntegrityHomeCard(vm: MainViewModel, ivm: IntegrityViewModel) {
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { ivm.pickFile(it) { vm.navigate(Screen.IntegritySetup) } }
    }
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
        Column(Modifier.padding(16.dp)) {
            Text("🛡️ Kiểm tra APK trước khi cài", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(
                "Xác minh chữ ký, đối chiếu khóa ký với nguồn công bố, transparency log, reproducible build, " +
                    "Code Transparency, khóa dùng chung, mạo danh và split-view.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = { pick.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "application/zip")) },
                enabled = !ivm.busy, modifier = Modifier.fillMaxWidth(),
            ) { Text("Chọn file APK / APKS / XAPK") }
            OutlinedButton(
                onClick = { ivm.loadInstalled(); vm.navigate(Screen.IntegrityPicker) },
                enabled = !ivm.busy, modifier = Modifier.fillMaxWidth(),
            ) { Text("Kiểm tra app đã cài (tùy chọn)") }
        }
    }
}

@Composable
fun IntegrityPickerScreen(vm: MainViewModel, ivm: IntegrityViewModel) {
    var query by remember { mutableStateOf("") }
    val list = ivm.installed.filter { query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true) }
    Column {
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true,
            label = { Text("Tìm app") }, modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
        Row(Modifier.padding(horizontal = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = ivm.includeSystem, onCheckedChange = { ivm.includeSystem = it; ivm.loadInstalled() })
            Spacer(Modifier.width(8.dp))
            Text("Hiện cả app hệ thống", style = MaterialTheme.typography.bodyMedium)
        }
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(list, key = { it.packageName }) { a ->
                Card(Modifier.fillMaxWidth().clickable(enabled = !ivm.busy) { ivm.pickInstalled(a.packageName) { vm.navigate(Screen.IntegritySetup) } }) {
                    Column(Modifier.padding(12.dp)) {
                        Text(a.label, fontWeight = FontWeight.SemiBold)
                        Text(a.packageName, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
fun IntegritySetupScreen(vm: MainViewModel, ivm: IntegrityViewModel) {
    val b = ivm.bundle ?: return
    val o = ivm.options
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Card {
            Column(Modifier.padding(14.dp)) {
                Text(b.displayName, style = MaterialTheme.typography.titleMedium)
                Text(
                    if (b.installedPackage != null) "App đã cài · ${b.installedPackage}" else "File chưa cài" +
                        if (b.splits.isNotEmpty()) " · gói ${b.splits.size + 1} APK" else "",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Text("Thông tin công bố (không bắt buộc, giúp kết quả chắc chắn hơn)", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = o.officialFingerprints, onValueChange = { ivm.options = o.copy(officialFingerprints = it) },
            label = { Text("SHA-256 khóa ký chính thức (dán từ trang developer)") }, modifier = Modifier.fillMaxWidth(), minLines = 2,
        )
        OutlinedTextField(
            value = o.officialFileChecksum, onValueChange = { ivm.options = o.copy(officialFileChecksum = it) },
            label = { Text("SHA-256 của file APK do developer công bố") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        )
        OutlinedTextField(
            value = o.website, onValueChange = { ivm.options = o.copy(website = it) },
            label = { Text("Website chính thức (để đọc assetlinks.json)") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        )
        OutlinedTextField(
            value = o.ctKeyFingerprints, onValueChange = { ivm.options = o.copy(ctKeyFingerprints = it) },
            label = { Text("SHA-256 khóa Code Transparency (nếu developer công bố)") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
        )
        HorizontalDivider()
        ToggleRow("Tra cứu trực tuyến", "Google Play, F-Droid, IzzyOnDroid, log Google, website developer", o.online) { ivm.options = o.copy(online = it) }
        if (o.online) {
            ToggleRow("Tra metadata trên Google Play", "Gửi package name tới Google Play", o.checkGooglePlay) { ivm.options = o.copy(checkGooglePlay = it) }
            ToggleRow("Tra reproducible build IzzyOnDroid", "Tải chỉ mục ~6,5 MB, lưu 1 ngày", o.checkIzzy) { ivm.options = o.copy(checkIzzy = it) }
            ToggleRow("Tra log công khai Sigstore Rekor", "Khi app không có trong log Google; chỉ gửi SHA-256 của file", o.checkRekor) { ivm.options = o.copy(checkRekor = it) }
            Text("Phạm vi quét transparency log của Google", style = MaterialTheme.typography.bodyMedium)
            Text("Chỉ áp dụng cho app Google; quét càng rộng càng tốn dữ liệu.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            // Ba ô chia đều chiều ngang, cùng chiều cao.
            Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(Triple(100, "Nhanh", "~3 MB"), Triple(300, "Vừa", "~8 MB"), Triple(1000, "Sâu", "~27 MB")).forEach { (n, name, size) ->
                    ScopeOption(
                        selected = o.googleLogBundles == n,
                        title = "${n * 256 / 1000}k bản ghi",
                        subtitle = "$name · $size",
                        modifier = Modifier.weight(1f).fillMaxHeight(),
                    ) { ivm.options = o.copy(googleLogBundles = n) }
                }
            }
        }
        Button(onClick = { ivm.run { vm.navigate(Screen.IntegrityResult) } }, enabled = !ivm.busy, modifier = Modifier.fillMaxWidth()) {
            Text("Bắt đầu kiểm tra")
        }
        Text(DISCLAIMER, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun ScopeOption(selected: Boolean, title: String, subtitle: String, modifier: Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(12.dp)
    val border = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
    Column(
        modifier
            .clip(shape)
            .background(if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface)
            .border(if (selected) 2.dp else 1.dp, border, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 6.dp, vertical = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(title, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold, maxLines = 1, textAlign = TextAlign.Center)
        Text(subtitle, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, textAlign = TextAlign.Center)
    }
}

@Composable
private fun ToggleRow(title: String, sub: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
fun IntegrityResultScreen(ivm: IntegrityViewModel) {
    val r = ivm.report ?: return
    val a = r.input.apk
    val ctx = LocalContext.current
    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        // ---- Kết luận
        Card(colors = CardDefaults.cardColors(containerColor = verdictColor(r.verdict))) {
            Column(Modifier.padding(16.dp)) {
                Text("${r.verdict.icon}  ${r.verdict.label}", color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(4.dp))
                Text(r.verdict.explain, color = Color.White, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                r.verdictReasons.forEach { Text("• $it", color = Color.White, style = MaterialTheme.typography.bodyMedium) }
                Spacer(Modifier.height(10.dp))
                Text(
                    "Điểm tin cậy: ${r.score.total}/100 · ${r.score.band}",
                    color = Color.White, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium,
                )
            }
        }
        ScoreCard(r)
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF4E0))) {
            Text("ℹ️ $DISCLAIMER", Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall, color = Color(0xFF5A4300))
        }

        // ---- App
        Card {
            Column(Modifier.padding(14.dp)) {
                Text(a.label, style = MaterialTheme.typography.titleLarge)
                Text(a.packageName, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                Text("Phiên bản ${a.versionName ?: "?"} (${a.versionCode}) · targetSdk ${a.targetSdk ?: "?"}", style = MaterialTheme.typography.bodySmall)
                Text("SHA-256 file: ${a.fileSha256}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
        }

        // ---- Các kiểm tra
        Text("Các kiểm tra (${r.checks.count { it.status == CheckStatus.PASS }}/${r.checks.size} đạt)", style = MaterialTheme.typography.titleMedium)
        r.checks.forEach { CheckCard(it) }

        // ---- Đối chiếu nguồn công bố
        if (r.input.sources.isNotEmpty()) {
            Text("Đối chiếu nhiều nguồn công bố", style = MaterialTheme.typography.titleMedium)
            Card {
                Column(Modifier.padding(12.dp)) {
                    r.input.sources.forEach { s ->
                        Row(Modifier.padding(vertical = 4.dp)) {
                            Text(s.status.icon, Modifier.width(28.dp))
                            Column {
                                Text(s.source, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium)
                                Text(s.note, style = MaterialTheme.typography.bodySmall)
                                s.publishedFingerprints.take(3).forEach { Text(it, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace) }
                            }
                        }
                    }
                }
            }
        }

        // ---- Thiếu so với app uy tín
        Text("Còn thiếu so với một app uy tín cơ bản (${r.missingBaseline.size}/${r.baseline.size})", style = MaterialTheme.typography.titleMedium)
        Card {
            Column(Modifier.padding(12.dp)) {
                if (r.missingBaseline.isEmpty()) Text("Không thiếu mục nào. 👍")
                r.baseline.groupBy { it.group }.forEach { (g, items) ->
                    Text(g, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 6.dp))
                    items.forEach { b ->
                        Row(Modifier.padding(vertical = 2.dp)) {
                            Text(when (b.present) { true -> "✅"; false -> "❌"; null -> "⚪" }, Modifier.width(28.dp))
                            Column {
                                Text(b.title, style = MaterialTheme.typography.bodyMedium)
                                if (b.present == false) Text(b.hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (b.present == null) Text("Chưa có dữ liệu để đánh giá", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        }

        OutlinedButton(onClick = {
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "Kiểm tra toàn vẹn: ${a.label}")
                putExtra(Intent.EXTRA_TEXT, IntegrityMarkdown.build(r))
            }
            ctx.startActivity(Intent.createChooser(send, "Chia sẻ báo cáo"))
        }, modifier = Modifier.fillMaxWidth()) { Text("Chia sẻ báo cáo (Markdown)") }
        Spacer(Modifier.height(24.dp))
    }
}

/** Bảng điểm tin cậy: điểm từng tiêu chí và (khi mở) toàn bộ tiêu chí chấm điểm. */
@Composable
private fun ScoreCard(r: com.mixedsignals.checker.domain.integrity.IntegrityReport) {
    var showCriteria by remember { mutableStateOf(false) }
    Card {
        Column(Modifier.padding(14.dp)) {
            Text("Cách tính điểm tin cậy (${r.score.total}/100)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            r.score.items.forEach { s ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(s.criterion, style = MaterialTheme.typography.bodyMedium)
                        Text(s.note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(
                        "${s.earned}/${s.max}", fontWeight = FontWeight.Bold,
                        color = when { s.earned == s.max -> Color(0xFF2E7D32); s.earned == 0 -> Color(0xFFD32F2F); else -> Color(0xFFE08A00) },
                    )
                }
                // Thanh tiến độ của tiêu chí.
                Box(Modifier.fillMaxWidth().height(4.dp).background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(2.dp))) {
                    Box(Modifier.fillMaxWidth(s.earned.toFloat() / s.max).height(4.dp).background(MaterialTheme.colorScheme.primary, RoundedCornerShape(2.dp)))
                }
            }
            r.score.capNote?.let { Text("⚠️ $it", style = MaterialTheme.typography.bodySmall, color = Color(0xFFD32F2F), modifier = Modifier.padding(top = 8.dp)) }
            Text(
                if (showCriteria) "▲ Ẩn tiêu chí chấm điểm" else "▼ Xem tiêu chí chấm điểm",
                style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.clickable { showCriteria = !showCriteria }.padding(top = 8.dp),
            )
            if (showCriteria) {
                Scoring.INTEGRITY_CRITERIA.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall) }
                Text(
                    "Điểm cho biết độ mạnh của bằng chứng; kết luận 5 mức vẫn theo các điều kiện bắt buộc ở trên.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp),
                )
            }
        }
    }
}

@Composable
private fun CheckCard(c: CheckResult) {
    var open by remember(c.id) { mutableStateOf(c.status == CheckStatus.FAIL) }
    Card(Modifier.fillMaxWidth().clickable { open = !open }) {
        Row(Modifier.padding(12.dp)) {
            Text(c.status.icon, fontSize = 20.sp, modifier = Modifier.width(34.dp))
            Column(Modifier.weight(1f)) {
                Text(c.title, fontWeight = FontWeight.SemiBold)
                Text(c.status.label, style = MaterialTheme.typography.labelSmall, color = statusColor(c.status))
                Text(c.summary, style = MaterialTheme.typography.bodySmall)
                if (open && c.details.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    c.details.forEach { Text(it, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace) }
                }
            }
            if (c.details.isNotEmpty()) Text(if (open) "▲" else "▼")
        }
    }
}

/** Hiện lỗi của phần kiểm tra toàn vẹn qua snackbar chung. */
@Composable
fun IntegrityErrors(vm: MainViewModel, ivm: IntegrityViewModel) {
    LaunchedEffect(ivm.error) {
        ivm.error?.let { vm.message = it; ivm.error = null }
    }
}
