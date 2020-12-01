/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: copy to system
    Rule id: 1051
    Created at: 2015-12-09 07:16:02
    Updated at: 2015-12-09 07:43:41
    
    Rating: #0
    Total detections: 124408
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
	$a = /\cp.{1,} \/system\/app/
	$b = /\cat.{1,} \/system\/app/
	$c = /cp [0-9a-zA-Z] {1,}\/system\/app/
    $d = /cat [0-9a-zA-Z] {1,}\/system\/app/
	condition:
		any of them
		
}
