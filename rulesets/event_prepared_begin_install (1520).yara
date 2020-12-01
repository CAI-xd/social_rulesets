/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: event_prepared_begin_install
    Rule id: 1520
    Created at: 2016-06-16 14:45:53
    Updated at: 2016-06-16 14:46:02
    
    Rating: #0
    Total detections: 4
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
		$l = "event_prepared_begin_install"

	condition:
		any of them
		}
