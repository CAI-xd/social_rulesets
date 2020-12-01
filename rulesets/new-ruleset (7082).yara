/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: astic
    Rule name: New Ruleset
    Rule id: 7082
    Created at: 2020-10-06 14:10:10
    Updated at: 2020-10-06 14:28:33
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule is_apk : file_type
{
  meta:
    description = "APK"

  strings:
    $zip_head = "PK"
    $manifest = "AndroidManifest.xml"

  condition:
    $zip_head at 0 and $manifest and #manifest >= 2
}


rule vkey_protector : obfuscator
{
  meta:
    description = "V-Key"

  strings:
    $l1_1 = "lib/arm64-v8a/libvosWrapperEx.so"
    $l1_2 = "lib/armeabi-v7a/libvosWrapperEx.so"
    $l1_3 = "lib/armeabi/libvosWrapperEx.so"
    $l1_4 = "lib/mips/libvosWrapperEx.so"
    $l1_5 = "lib/mips64/libvosWrapperEx.so"
    $l1_6 = "lib/x86/libvosWrapperEx.so"
    $l1_7 = "lib/x86_64/libvosWrapperEx.so"
    $l2_1 = "lib/arm64-v8a/libchecks.so"
    $l2_2 = "lib/armeabi-v7a/libchecks.so"
    $l2_3 = "lib/armeabi/libchecks.so"
    $l2_4 = "lib/mips/libchecks.so"
    $l2_5 = "lib/mips64/libchecks.so"
    $l2_6 = "lib/x86/libchecks.so"
    $l2_7 = "lib/x86_64/libchecks.so"
    $l3_1 = "lib/arm64-v8a/libpki.so"
    $l3_2 = "lib/armeabi-v7a/libpki.so"
    $l3_3 = "lib/armeabi/libpki.so"
    $l3_4 = "lib/mips/libpki.so"
    $l3_5 = "lib/mips64/libpki.so"
    $l3_6 = "lib/x86/libpki.so"
    $l3_7 = "lib/x86_64/libpki.so"
    $l4_1 = "lib/arm64-v8a/libloadTA.so"
    $l4_2 = "lib/armeabi-v7a/libloadTA.so"
    $l4_3 = "lib/armeabi/libloadTA.so"
    $l4_4 = "lib/mips/libloadTA.so"
    $l4_5 = "lib/mips64/libloadTA.so"
    $l4_6 = "lib/x86/libloadTA.so"
    $l4_7 = "lib/x86_64/libloadTA.so"

  condition:
    any of them and is_apk
}
