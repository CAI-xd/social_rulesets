/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5488
    Created at: 2019-04-24 08:11:29
    Updated at: 2019-05-13 09:19:20
    
    Rating: #0
    Total detections: 3032
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Trojan_FakeAd_A
{  
	meta:
		description = "Rule used to detect Jio and PayTM fakeapp"
		source = "Lastline"
		Author = "Anand Singh"
		Date = "04/12/2019"
	
	strings:
		$a1 = "bhadva.chromva.jio" wide
		$a2 = ".jio4goffers." wide
		
		$b1 = "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE" wide
		$b2 = {2E 00 6A 00 69 00 6F 00 ?? 00 67 00 6F 00 66 00 66 00 65 00 72 00 73 00 00 00} //j.i.o.?.g.o.f.f.e.r.s
		$b3 ={00 6A 00 69 00 6F 00 ?? 00 6F 00 66 00 66 00 65 00 72 00 73 00 00}

		$c1 = "android.permission.READ_CONTACTS" wide
		$c2 = "android.permission.READ_SMS" wide
		$c3 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c4 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}


	condition:
		$hexstr_targetSdkVersion and ((any of ($a*) or (any of ($b*)) and 3 of ($c*)))

}
