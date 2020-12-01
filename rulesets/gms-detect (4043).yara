/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: GMS Detect
    Rule id: 4043
    Created at: 2018-01-24 16:02:11
    Updated at: 2018-01-24 16:03:58
    
    Rating: #0
    Total detections: 942327
*/

import "androguard"
import "file"
import "cuckoo"


rule GMS : jcarneiro
{
	meta:
		description = "This rule detects the usage of Google Mobile Services"

	strings:
		$a = "com.google.android.gms"

	condition:
		$a	
		
}
