# consumer-rules.pro — applied to any module that depends on :common-security.
# Keep the public API surface — Tamper, A11yProbe, DeviceProfile, SecureButton/
# SecureOutlinedButton — so consumers can call them after R8 shrinking.
-keep class com.understory.security.Tamper { *; }
-keep class com.understory.security.Tamper$Report { *; }
-keep class com.understory.security.A11yProbe { *; }
-keep class com.understory.security.A11yProbe$State { *; }
-keep class com.understory.security.DeviceProfile { *; }
