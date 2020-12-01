/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fvrmatteo
    Rule name: SecondHand
    Rule id: 4041
    Created at: 2018-01-23 20:20:16
    Updated at: 2018-02-28 10:57:26
    
    Rating: #0
    Total detections: 4
*/

import "androguard"
import "droidbox"
import "file"

rule SecondHand
{
  meta:
	description = "Trojan SecondHand"
	
  strings:
    $lib_arm = "lib/armeabi/libsecondhand.so"
    $lib_armv7 = "lib/armeabi-v7a/libsecondhand.so"
	$lib_armv8 = "lib/arm64-v8a/libsecondhand.so"
	$lib_mips = "lib/mips/libsecondhand.so"
	$lib_mips64 = "lib/mips64/libsecondhand.so"
	$lib_x86 = "lib/x86/libsecondhand.so"
	$lib_x64 = "lib/x86_64/libsecondhand.so"

  condition:
    $lib_arm or $lib_armv7 or $lib_armv8 or $lib_mips or $lib_mips64 or $lib_x86 or $lib_x64 or droidbox.library(/libsecondhand\.so/) or droidbox.written.filename("0.xml") or droidbox.written.filename("F.xml")
}
