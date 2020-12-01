/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: Leanback
    Rule id: 5147
    Created at: 2018-12-13 16:20:24
    Updated at: 2018-12-13 22:06:09
    
    Rating: #0
    Total detections: 46017
*/

import "androguard"
import "file"
import "cuckoo"


rule Leanback : jcarneiro
{
	strings:
		$a = "leanback"

	condition:
		$a	
}
