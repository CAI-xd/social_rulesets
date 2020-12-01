/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: New Ruleset
    Rule id: 6857
    Created at: 2020-04-21 10:31:46
    Updated at: 2020-04-21 10:32:14
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule apk_inside
{


	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
		
}
