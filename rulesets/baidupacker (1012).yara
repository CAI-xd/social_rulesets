/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: BaiduPacker
    Rule id: 1012
    Created at: 2015-11-13 10:51:50
    Updated at: 2015-11-13 10:56:09
    
    Rating: #0
    Total detections: 23235
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "BaiduPacker"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "com.baidu.protect.StubApplication"
		$strings_a = "com.baidu.protect.StubProvider"
		$strings_c = "com.baidu.protect.A"
		$strings_d = "baiduprotect.jar"
		$strings_d = "libbaiduprotect"

	condition:
		any of them
}
