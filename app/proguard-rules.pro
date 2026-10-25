# apksig đọc cấu trúc ASN.1 (chữ ký v1/PKCS#7, chứng chỉ) bằng reflection trên các field có annotation
# @Asn1Class/@Asn1Field. Nếu R8 xóa field/annotation, mọi APK có chữ ký v1 sẽ bị báo sai là "không hợp lệ".
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# Chỉ dùng Ed25519 của BouncyCastle; bỏ cảnh báo về các phần không dùng.
-dontwarn org.bouncycastle.**
