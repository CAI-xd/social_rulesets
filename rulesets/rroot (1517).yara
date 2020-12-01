/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: rroot
    Rule id: 1517
    Created at: 2016-06-16 14:10:35
    Updated at: 2016-06-16 14:11:18
    
    Rating: #0
    Total detections: 574
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
		$l = "r_root_true"

	condition:
		any of them
		}
