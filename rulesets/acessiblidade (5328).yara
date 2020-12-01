/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: acessiblidade
    Rule id: 5328
    Created at: 2019-02-28 21:20:41
    Updated at: 2019-02-28 21:21:33
    
    Rating: #0
    Total detections: 3
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
		$a = "ativar o servi"
		$b = "acessiblidade"

	condition:
		$a and $b
		
}
