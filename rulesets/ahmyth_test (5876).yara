/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Ahmyth_test
    Rule id: 5876
    Created at: 2019-08-28 00:59:33
    Updated at: 2019-08-28 01:01:16
    
    Rating: #0
    Total detections: 19
*/

import "androguard"
import "file"
import "cuckoo"


rule Ahmyth_test
{
	meta:
		description = "This rule detects ahmyth packaged apps"
		
	strings:
		$a1 = "done"
		$a2 = "collecting"
		$a3 = "cannot"
		$a5 = "inaccessible"
		$a6 = "Network"
		$a7 = "DIRR"
		$a8 = "external storage access error"
		
	condition:
		all of ($a*)
		
}
