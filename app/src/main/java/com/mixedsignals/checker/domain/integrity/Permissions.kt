package com.mixedsignals.checker.domain.integrity

/** Mức rủi ro của quyền (bảng phân loại đã thống nhất). */
enum class RiskTier(val icon: String, val label: String, val advice: String) {
    RED("🔴", "Cảnh báo đỏ", "App xin quyền liên quan tới thông báo, tiền, mật khẩu hoặc thông tin cá nhân. Không nên cài nếu không thật sự cần."),
    YELLOW("🟡", "Rủi ro trung bình", "Cân nhắc: quyền có khớp với chức năng của app không. Chỉ cấp khi đang dùng."),
    GREEN("🟢", "Chấp nhận cài đặt", "App chỉ xin các quyền rủi ro thấp."),
}

data class PermissionInfo(val tier: RiskTier, val group: String, val description: String)

data class AssessedPermission(val name: String, val info: PermissionInfo, val viaComponent: String? = null)

data class PermissionAssessment(
    val overall: RiskTier,
    val items: List<AssessedPermission>,
    val manifestWarnings: List<Pair<RiskTier, String>>,
) {
    /** Điểm rủi ro quyền 0–100 (đỏ +30, vàng +10 mỗi mục; xem Scoring.PERMISSION_CRITERIA). */
    val score: Int get() = Scoring.permissionScore(items, manifestWarnings)

    fun byTier(t: RiskTier) = items.filter { it.info.tier == t }
}

object PermissionCatalog {
    private const val A = "android.permission."
    private const val NOTIF = "Thông báo"
    private const val MONEY_PASS = "Tiền / mật khẩu"
    private const val PERSONAL = "Thông tin cá nhân"
    private const val DEVICE = "Thiết bị"
    private const val NORMAL = "Thông thường"

    private val map: Map<String, PermissionInfo> = buildMap {
        fun red(p: String, g: String, d: String) = put(p, PermissionInfo(RiskTier.RED, g, d))
        fun yellow(p: String, g: String, d: String) = put(p, PermissionInfo(RiskTier.YELLOW, g, d))
        fun green(p: String, d: String) = put(p, PermissionInfo(RiskTier.GREEN, NORMAL, d))

        // ---- Đỏ: thông báo
        red(A + "BIND_NOTIFICATION_LISTENER_SERVICE", NOTIF, "Đọc toàn bộ thông báo của app khác (kể cả mã OTP, tin nhắn)")
        // ---- Đỏ: tiền / mật khẩu
        red(A + "BIND_ACCESSIBILITY_SERVICE", MONEY_PASS, "Trợ năng: đọc nội dung màn hình và tự bấm thay bạn (mã độc ngân hàng hay dùng)")
        red(A + "BIND_AUTOFILL_SERVICE", MONEY_PASS, "Dịch vụ tự điền: đọc mật khẩu, thẻ thanh toán khi điền form")
        red(A + "BIND_CREDENTIAL_PROVIDER_SERVICE", MONEY_PASS, "Nhà cung cấp mật khẩu/passkey cho hệ thống")
        red(A + "BIND_INPUT_METHOD", MONEY_PASS, "Bàn phím: thấy mọi thứ bạn gõ, kể cả mật khẩu")
        red(A + "BIND_DEVICE_ADMIN", MONEY_PASS, "Quản trị thiết bị: khóa máy, xóa dữ liệu, chống gỡ cài đặt")
        red(A + "BIND_VPN_SERVICE", MONEY_PASS, "VPN: toàn bộ lưu lượng mạng đi qua app")
        red(A + "SYSTEM_ALERT_WINDOW", MONEY_PASS, "Vẽ đè lên app khác (dùng để giả màn hình đăng nhập)")
        red(A + "REQUEST_INSTALL_PACKAGES", MONEY_PASS, "Cài app khác (có thể tải mã độc về sau)")
        red(A + "READ_SMS", MONEY_PASS, "Đọc tin nhắn SMS (mã OTP ngân hàng)")
        red(A + "RECEIVE_SMS", MONEY_PASS, "Nhận SMS (chặn mã OTP)")
        red(A + "SEND_SMS", MONEY_PASS, "Gửi SMS (có thể tốn tiền)")
        red(A + "RECEIVE_MMS", MONEY_PASS, "Nhận MMS")
        red(A + "RECEIVE_WAP_PUSH", MONEY_PASS, "Nhận tin WAP push")
        red(A + "CALL_PHONE", MONEY_PASS, "Gọi điện không cần xác nhận (có thể gọi số tính phí)")
        red(A + "USE_CREDENTIALS", MONEY_PASS, "Dùng thông tin đăng nhập tài khoản (Android cũ)")
        red(A + "MANAGE_ACCOUNTS", MONEY_PASS, "Quản lý tài khoản (Android cũ)")
        // ---- Đỏ: thông tin cá nhân
        red(A + "READ_CONTACTS", PERSONAL, "Đọc danh bạ")
        red(A + "WRITE_CONTACTS", PERSONAL, "Sửa danh bạ")
        red(A + "GET_ACCOUNTS", PERSONAL, "Xem danh sách tài khoản trên máy")
        red(A + "READ_CALL_LOG", PERSONAL, "Đọc nhật ký cuộc gọi")
        red(A + "WRITE_CALL_LOG", PERSONAL, "Sửa nhật ký cuộc gọi")
        red(A + "PROCESS_OUTGOING_CALLS", PERSONAL, "Xem/chuyển hướng cuộc gọi đi")
        red(A + "READ_PHONE_NUMBERS", PERSONAL, "Đọc số điện thoại của máy")
        red(A + "ACCESS_FINE_LOCATION", PERSONAL, "Vị trí chính xác")
        red(A + "ACCESS_BACKGROUND_LOCATION", PERSONAL, "Vị trí cả khi không dùng app")
        red(A + "MANAGE_EXTERNAL_STORAGE", PERSONAL, "Truy cập toàn bộ bộ nhớ")
        red(A + "BODY_SENSORS", PERSONAL, "Cảm biến cơ thể (nhịp tim…)")
        red(A + "BODY_SENSORS_BACKGROUND", PERSONAL, "Cảm biến cơ thể cả khi chạy nền")
        red(A + "PACKAGE_USAGE_STATS", PERSONAL, "Theo dõi bạn dùng app nào, bao lâu")

        // ---- Vàng
        yellow(A + "CAMERA", PERSONAL, "Máy ảnh")
        yellow(A + "RECORD_AUDIO", PERSONAL, "Ghi âm")
        yellow(A + "ACCESS_COARSE_LOCATION", PERSONAL, "Vị trí gần đúng")
        yellow(A + "READ_MEDIA_IMAGES", PERSONAL, "Đọc ảnh")
        yellow(A + "READ_MEDIA_VIDEO", PERSONAL, "Đọc video")
        yellow(A + "READ_MEDIA_AUDIO", PERSONAL, "Đọc file âm thanh")
        yellow(A + "READ_MEDIA_VISUAL_USER_SELECTED", PERSONAL, "Đọc ảnh/video bạn chọn")
        yellow(A + "READ_EXTERNAL_STORAGE", PERSONAL, "Đọc bộ nhớ chung")
        yellow(A + "WRITE_EXTERNAL_STORAGE", PERSONAL, "Ghi bộ nhớ chung")
        yellow(A + "READ_CALENDAR", PERSONAL, "Đọc lịch")
        yellow(A + "WRITE_CALENDAR", PERSONAL, "Sửa lịch")
        yellow(A + "ACTIVITY_RECOGNITION", PERSONAL, "Nhận diện hoạt động (đi bộ, lái xe…)")
        yellow(A + "READ_PHONE_STATE", DEVICE, "Thông tin điện thoại, trạng thái cuộc gọi")
        yellow(A + "ANSWER_PHONE_CALLS", DEVICE, "Trả lời cuộc gọi")
        yellow(A + "BLUETOOTH_SCAN", DEVICE, "Quét thiết bị Bluetooth lân cận")
        yellow(A + "BLUETOOTH_CONNECT", DEVICE, "Kết nối Bluetooth")
        yellow(A + "BLUETOOTH_ADVERTISE", DEVICE, "Phát Bluetooth")
        yellow(A + "NEARBY_WIFI_DEVICES", DEVICE, "Thiết bị Wi-Fi lân cận")
        yellow(A + "CHANGE_WIFI_STATE", DEVICE, "Bật/tắt, kết nối Wi-Fi")
        yellow(A + "ACCESS_LOCAL_NETWORK", DEVICE, "Truy cập thiết bị trong mạng nội bộ (LAN)")
        yellow(A + "NFC", DEVICE, "NFC (có thể dùng cho thanh toán)")
        yellow(A + "UWB_RANGING", DEVICE, "Định vị khoảng cách UWB")
        yellow(A + "QUERY_ALL_PACKAGES", DEVICE, "Xem danh sách mọi app đã cài")
        yellow(A + "WRITE_SETTINGS", DEVICE, "Đổi cài đặt hệ thống")
        yellow(A + "SCHEDULE_EXACT_ALARM", DEVICE, "Hẹn giờ chính xác")
        yellow(A + "USE_FULL_SCREEN_INTENT", DEVICE, "Hiện màn hình toàn phần (như cuộc gọi đến)")
        yellow(A + "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", DEVICE, "Chạy nền không bị giới hạn pin")
        yellow(A + "REQUEST_DELETE_PACKAGES", DEVICE, "Yêu cầu gỡ app khác")
        yellow(A + "ACCESS_NOTIFICATION_POLICY", DEVICE, "Thay đổi chế độ Không làm phiền")
        yellow(A + "FOREGROUND_SERVICE_LOCATION", PERSONAL, "Dịch vụ nền dùng vị trí")
        yellow(A + "FOREGROUND_SERVICE_CAMERA", PERSONAL, "Dịch vụ nền dùng máy ảnh")
        yellow(A + "FOREGROUND_SERVICE_MICROPHONE", PERSONAL, "Dịch vụ nền dùng micro")
        yellow("com.android.vending.BILLING", "Thanh toán trong app", "Mua hàng trong app qua Google Play")

        // ---- Xanh
        green(A + "INTERNET", "Kết nối Internet")
        green(A + "ACCESS_NETWORK_STATE", "Xem trạng thái mạng")
        green(A + "ACCESS_WIFI_STATE", "Xem trạng thái Wi-Fi")
        green(A + "CHANGE_NETWORK_STATE", "Đổi kết nối mạng")
        green(A + "VIBRATE", "Rung")
        green(A + "WAKE_LOCK", "Giữ máy không ngủ")
        green(A + "POST_NOTIFICATIONS", "Gửi thông báo (không đọc được thông báo của app khác)")
        green(A + "RECEIVE_BOOT_COMPLETED", "Khởi động cùng máy")
        green(A + "FOREGROUND_SERVICE", "Chạy dịch vụ có thông báo")
        green(A + "FOREGROUND_SERVICE_DATA_SYNC", "Đồng bộ dữ liệu nền")
        green(A + "FOREGROUND_SERVICE_MEDIA_PLAYBACK", "Phát nhạc nền")
        green(A + "FOREGROUND_SERVICE_SPECIAL_USE", "Dịch vụ nền đặc biệt")
        green(A + "FOREGROUND_SERVICE_SHORT_SERVICE", "Dịch vụ nền ngắn")
        green(A + "USE_BIOMETRIC", "Xác thực sinh trắc học (app không đọc được vân tay)")
        green(A + "USE_FINGERPRINT", "Xác thực vân tay (Android cũ)")
        green(A + "SET_WALLPAPER", "Đặt hình nền")
        green(A + "REORDER_TASKS", "Sắp xếp cửa sổ app")
        green(A + "EXPAND_STATUS_BAR", "Mở thanh trạng thái")
        green(A + "DOWNLOAD_WITHOUT_NOTIFICATION", "Tải xuống không thông báo")
        green("com.android.launcher.permission.INSTALL_SHORTCUT", "Tạo lối tắt")
        green("com.google.android.c2dm.permission.RECEIVE", "Nhận thông báo đẩy (FCM)")
        green("com.google.android.gms.permission.AD_ID", "Mã quảng cáo")
        green("com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE", "Nguồn giới thiệu cài đặt")
    }

    fun lookup(permission: String, ownPackage: String): PermissionInfo = map[permission] ?: when {
        // Quyền do chính app định nghĩa (ví dụ <package>.permission.C2D_MESSAGE) hoặc quyền nội bộ thư viện.
        permission.startsWith("$ownPackage.") || !permission.startsWith("android.permission.") ->
            PermissionInfo(RiskTier.GREEN, NORMAL, "Quyền riêng của app hoặc thư viện")
        else -> PermissionInfo(RiskTier.YELLOW, DEVICE, "Quyền hệ thống chưa phân loại — cần xem xét")
    }

    fun assess(apk: ApkEvidence): PermissionAssessment {
        val items = mutableListOf<AssessedPermission>()
        val seen = mutableSetOf<String>()
        for (c in apk.protectedComponents) {
            val info = map[c.permission] ?: continue
            if (seen.add(c.permission)) items += AssessedPermission(c.permission, info, c.name)
        }
        for (p in apk.requestedPermissions) {
            if (!seen.add(p)) continue
            items += if (p in apk.implicitPermissions) {
                // Developer không xin quyền này; hệ thống tự thêm để tương thích nên không tính vào mức rủi ro.
                AssessedPermission(p, PermissionInfo(RiskTier.GREEN, "Hệ thống tự thêm", "Android tự thêm để tương thích (app không khai báo): " + lookup(p, apk.packageName).description))
            } else AssessedPermission(p, lookup(p, apk.packageName))
        }
        val warnings = mutableListOf<Pair<RiskTier, String>>()
        val target = apk.targetSdk
        if (target != null && target < 23) {
            warnings += RiskTier.RED to "App nhắm Android cũ (targetSdk $target < 23): mọi quyền nguy hiểm được cấp ngay khi cài, không hỏi bạn."
        }
        if (apk.debuggable) warnings += RiskTier.RED to "App bật chế độ debug: có thể bị can thiệp, không phải bản phát hành chuẩn."
        if (apk.usesCleartextTraffic) warnings += RiskTier.YELLOW to "App cho phép kết nối không mã hóa (HTTP)."
        val sorted = items.sortedWith(compareBy<AssessedPermission> { it.info.tier.ordinal }.thenBy { it.name })
        val overall = (sorted.map { it.info.tier } + warnings.map { it.first }).minByOrNull { it.ordinal } ?: RiskTier.GREEN
        return PermissionAssessment(overall, sorted, warnings)
    }

    fun shortName(p: String) = p.substringAfterLast('.')
}
