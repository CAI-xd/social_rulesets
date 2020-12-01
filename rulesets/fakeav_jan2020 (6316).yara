/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: FakeAV_Jan2020
    Rule id: 6316
    Created at: 2020-01-23 01:10:22
    Updated at: 2020-01-23 20:08:48
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule FakeAV_Jan2020
{
	meta:
		description = "This rule detects Fake Av"
		
	strings:
		$a1 = "whiteList"
        $a2 = "blackListPackages"
        $a3 = "blackListActivities"
        $a4 = "permissions"
        

	condition:
		all of ($a*)
		
}
