/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5932
    Created at: 2019-10-04 08:42:34
    Updated at: 2019-11-05 06:54:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Trojan_Ransomware_Coin
{  
	meta:
		Author = "Anand Singh"
		Date = "04/12/2019"
	
	strings:
	
		$a1 = "For correct operation of the program, you must confirm"
		$a2 = "android.app.action.ADD_DEVICE_ADMIN"
		$a3 = "isAutoStartEnabled"


	condition:
		$a1 and $a2 and $a3

}
