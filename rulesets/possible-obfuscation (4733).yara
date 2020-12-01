/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: Possible obfuscation
    Rule id: 4733
    Created at: 2018-08-03 10:56:20
    Updated at: 2018-08-03 11:01:27
    
    Rating: #0
    Total detections: 33847
*/

import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Obfuscation going on"

	strings:
		$yes_1 = "obfuscate" nocase
		$yes_2 = "obfuscation" nocase
		$yes_3 = "obfuscated" nocase
		$yes_4 = "deobfuscat" nocase

		$no1 = "obfuscatedIdentifier" nocase
		$no2 = "com.android.vending.licensing.AESObfuscator-1" nocase
		$no3 = "ObfuscatedCall"
		$no4 = "ObfuscatedCallP"
		$no5 = "ObfuscatedCallRet"
		$no6 = "ObfuscatedCallRetP"
		$no7 = "ObfuscatedFunc"
		$no8 = "ObfuscatedAddress"
		$no9 = "LVLObfusca"

	condition:
		any of ($yes_*) and not any of ($no*)
}
