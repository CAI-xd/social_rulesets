/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Fabric
    Rule id: 1084
    Created at: 2015-12-22 09:04:26
    Updated at: 2015-12-22 09:04:56
    
    Rating: #0
    Total detections: 128351
*/

import "androguard"
import "file"
import "cuckoo"


rule fabric : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$b = "io.fabric.sdk.android:fabric"
	condition:
		any of them
		
}
