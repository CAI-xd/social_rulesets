/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: ptrace
    Rule id: 1500
    Created at: 2016-06-13 11:56:34
    Updated at: 2016-06-13 11:56:59
    
    Rating: #0
    Total detections: 15383
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
		$l = "ptrace_attach"

	condition:
		any of them
		
}
