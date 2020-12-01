/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: FakeAV2_Jan2020
    Rule id: 6317
    Created at: 2020-01-24 01:15:51
    Updated at: 2020-01-24 01:16:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule FakeAV2_Jan2020
{
	meta:
		description = "This rule detects Fake Av"
		
	strings:
		$a1 = "whitelist" nocase
        $a2 = "blacklistpackages" nocase
        $a3 = "blacklistactivities" nocase
        $a4 = "permissions" nocase
        

	condition:
		all of ($a*)
		
}
