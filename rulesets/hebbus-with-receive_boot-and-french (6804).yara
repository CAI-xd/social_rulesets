/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Erikvv
    Rule name: Hebbus (with Receive_Boot and french)
    Rule id: 6804
    Created at: 2020-03-27 20:12:04
    Updated at: 2020-03-30 14:28:24
    
    Rating: #0
    Total detections: 166
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
		$a = "FRENCH_CUISINE"
	
	condition:
		
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and $a
	

}
