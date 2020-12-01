/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: apkprotect Packer
    Rule id: 6246
    Created at: 2019-12-24 00:36:44
    Updated at: 2019-12-25 21:34:05
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a1 = /lib\/[x86\_64|armeabi\-v7a|arm64\-v8a|x86]\/libapkprotect\.so/
		$a2 = "assets/apkprotect.bin"
		$a3 = "assets/apkprotect/classes.dex.bin"
		$a4 = "apkprotect-build.properties"
		$v1  = "Protected-by: ApkProtector 6.5"
		$v2  = "Protected-by: ApkProtector 6.4"
		$v3  = "Protected-by: ApkProtector 6."

	condition:
		1 of ($v*) and 2 of ($a*)
		
}
