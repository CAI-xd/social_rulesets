/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: possible_miner_test
    Rule id: 4182
    Created at: 2018-02-07 23:18:20
    Updated at: 2018-02-07 23:59:07
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"

rule possible_miner_test
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"

	strings:
		$a_1 = "loadUrl"
		$a_2 = "file"
		$a_3 = "android_asset"
		$a_4 = "html"
		$a_5 = "webView"
					
	condition:
		all of ($a_*)
						
}
