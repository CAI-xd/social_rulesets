/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: sorter_pill
    Rule id: 4159
    Created at: 2018-02-05 00:15:11
    Updated at: 2018-05-13 09:09:20
    
    Rating: #0
    Total detections: 1
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
		$a = "06741d050adeb395"
		$b = "351451208401216"
		$c = "00:26:37:17:3C:71"
		

	condition:
		any of them
		
}
