/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: loadweb
    Rule id: 6143
    Created at: 2019-11-28 08:52:05
    Updated at: 2019-11-28 08:53:20
    
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
		$a = ".method public LoadWeb()V"
		$b = ".method private loadWebsite()V"

	condition:
		any of them
		
}
