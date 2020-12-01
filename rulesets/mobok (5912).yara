/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Rebensk
    Rule name: MobOk
    Rule id: 5912
    Created at: 2019-09-27 11:18:24
    Updated at: 2019-09-29 06:13:02
    
    Rating: #0
    Total detections: 2
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects MobOK Variants"
		

	strings:
		$a1 = "okyesmobi"
		$a2 = "52.221.7.34"
		$a3 = "45.79.19.59"
		$a4 = "bb.rowute.com"
		$a5 = "koapkmobi.com"

	condition:
		any of them
		
}
