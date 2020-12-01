/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: Hebbus1 "ASadsdk"
    Rule id: 6805
    Created at: 2020-03-28 07:29:18
    Updated at: 2020-03-30 13:53:48
    
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
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"

	strings:
		$a = "ASadsdk"

	condition:
		
		androguard.permission(/android.permission.INTERNET/) and $a

}
