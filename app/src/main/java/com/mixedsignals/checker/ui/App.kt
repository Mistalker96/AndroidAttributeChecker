package com.mixedsignals.checker.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mixedsignals.checker.domain.StatsSection
import com.mixedsignals.checker.domain.model.ConfidenceLevel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

fun fmtDate(t: Long): String = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault()).format(Date(t))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(vm: MainViewModel, ivm: IntegrityViewModel) {
    AppTheme {
        val snackbar = remember { SnackbarHostState() }
        LaunchedEffect(vm.message) {
            vm.message?.let { snackbar.showSnackbar(it); vm.message = null }
        }
        IntegrityErrors(vm, ivm)
        BackHandler(enabled = vm.backStack.size > 1) { vm.back() }
        val screen = vm.screen
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            when (screen) {
                                Screen.Home -> "Attribution Checker"
                                Screen.AppList -> "Danh sách app"
                                is Screen.Detail -> "Chi tiết tín hiệu"
                                Screen.Glossary -> "Thuật ngữ"
                                Screen.IntegrityPicker -> "Chọn app đã cài"
                                Screen.IntegritySetup -> "Thông tin kiểm tra"
                                Screen.IntegrityResult -> "Kết quả toàn vẹn"
                            },
                        )
                    },
                    navigationIcon = {
                        if (vm.backStack.size > 1) TextButton(onClick = { vm.back() }) { Text("‹ Quay lại") }
                    },
                )
            },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { pad ->
            Column(Modifier.padding(pad).fillMaxSize()) {
                if (vm.busy || ivm.busy) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    val p = if (ivm.busy) ivm.progress else vm.progress
                    if (p.isNotEmpty()) {
                        Text(p, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp))
                    }
                }
                when (screen) {
                    Screen.Home -> HomeScreen(vm, ivm)
                    Screen.AppList -> AppListScreen(vm)
                    is Screen.Detail -> DetailScreen(vm, screen)
                    Screen.Glossary -> GlossaryScreen()
                    Screen.IntegrityPicker -> IntegrityPickerScreen(vm, ivm)
                    Screen.IntegritySetup -> IntegritySetupScreen(vm, ivm)
                    Screen.IntegrityResult -> IntegrityResultScreen(ivm)
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(vm: MainViewModel, ivm: IntegrityViewModel) {
    val pickApk = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(vm::analyzeFile)
    }
    val saveReport = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/markdown")) { uri ->
        uri?.let(vm::exportMarkdown)
    }
    LazyColumn(
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { IntegrityHomeCard(vm, ivm) }
        item {
            Card {
                Column(Modifier.padding(16.dp)) {
                    Text("Tín hiệu attribution có đủ và ổn định không?", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Hiện thực đóng góp 1 của paper \"Mixed Signals\" (§5): với mỗi app, kiểm tra tín hiệu nào " +
                            "bị thiếu (subject chứng chỉ, metadata trên store) và tín hiệu nào thay đổi giữa các lần quét. " +
                            "Quét nhiều lần theo thời gian để đo độ biến động.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = vm::scan, enabled = !vm.busy, modifier = Modifier.weight(1f)) { Text("Quét app đã cài") }
                OutlinedButton(
                    onClick = { pickApk.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) },
                    enabled = !vm.busy,
                    modifier = Modifier.weight(1f),
                ) { Text("Phân tích file APK") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = vm.includeSystem, onCheckedChange = { vm.includeSystem = it })
                Spacer(Modifier.padding(4.dp))
                Text("Bao gồm app hệ thống", style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (vm.reports.isNotEmpty()) {
            item { SummaryCard(vm) }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { vm.navigate(Screen.AppList) }, modifier = Modifier.fillMaxWidth()) { Text("Xem danh sách ${vm.reports.size} app") }
                    if (vm.busy && vm.progress.startsWith("Tra cứu Google Play")) {
                        OutlinedButton(onClick = vm::cancelBulk, modifier = Modifier.fillMaxWidth()) { Text("Dừng tra cứu") }
                    } else {
                        OutlinedButton(onClick = vm::fetchPlayAll, enabled = !vm.busy, modifier = Modifier.fillMaxWidth()) {
                            Text("Tra cứu Google Play cho tất cả app")
                        }
                    }
                    OutlinedButton(onClick = { saveReport.launch("attribution-report.md") }, modifier = Modifier.fillMaxWidth()) {
                        Text("Xuất báo cáo Markdown")
                    }
                }
            }
            items(vm.stats) { StatsCard(it) }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { vm.navigate(Screen.Glossary) }) { Text("Thuật ngữ & cách đọc kết quả") }
                TextButton(onClick = vm::clearData, enabled = !vm.busy) { Text("Xóa lịch sử") }
            }
        }
    }
}

@Composable
private fun SummaryCard(vm: MainViewModel) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Text("Kết quả lần quét", style = MaterialTheme.typography.titleMedium)
            vm.lastScanAt?.let { Text("Lúc ${fmtDate(it)} · đã quét tổng cộng ${vm.trackedScans} lần", style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(8.dp))
            for (l in ConfidenceLevel.entries) {
                val n = vm.reports.count { it.level == l }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    ScoreDot(levelColor(l))
                    Text(l.label, Modifier.weight(1f).padding(start = 8.dp))
                    Text("$n app", fontWeight = FontWeight.Bold)
                }
            }
            if (vm.trackedScans < 2) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Cần quét ít nhất 2 lần (cách nhau một thời gian) để đo độ biến động.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun StatsCard(sec: StatsSection) {
    Card {
        Column(Modifier.padding(16.dp)) {
            Text(sec.title, style = MaterialTheme.typography.titleSmall)
            Text(sec.note, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Row {
                Text("Chỉ số", Modifier.weight(2.2f), style = MaterialTheme.typography.labelSmall)
                Text("Máy này", Modifier.weight(1.2f), style = MaterialTheme.typography.labelSmall)
                Text("Paper", Modifier.weight(1.1f), style = MaterialTheme.typography.labelSmall)
            }
            HorizontalDivider()
            for (r in sec.rows) {
                Row(Modifier.padding(vertical = 3.dp)) {
                    Text(r.label, Modifier.weight(2.2f), style = MaterialTheme.typography.bodySmall)
                    Text("${r.percentText} (${r.count}/${r.total})", Modifier.weight(1.2f), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    Text(r.paperValue ?: "", Modifier.weight(1.1f), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
