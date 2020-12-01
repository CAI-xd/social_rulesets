/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Komerso
    Rule name: 2357070 Droid
    Rule id: 7260
    Created at: 2020-11-11 16:19:25
    Updated at: 2020-11-11 16:40:14
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects DroidKhungFu1 like applications"

	strings:
	$a1 = "onCreate.java"
	$a2 = "updateInfo.java"
	$a3 = "cpLegacyRes.java"
	$a4 = "decrypt.java"
	$a5 = "doExecuteTask.java"
	$a6 = "DeleteApp.java"
	
	
	condition:
		androguard.service(".google.ssearch") and
		all of ($a*)
		
		
		
}
