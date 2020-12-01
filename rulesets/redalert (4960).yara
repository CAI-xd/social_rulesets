/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: albertosegura
    Rule name: RedAlert
    Rule id: 4960
    Created at: 2018-10-09 10:12:32
    Updated at: 2018-10-09 10:14:39
    
    Rating: #0
    Total detections: 141
*/

import "androguard"
import "file"
import "cuckoo"


rule redalert {

	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = ">sban</string>"
		$string_3 = ">gt</string>"
	condition:
		1 of ($string_*)
}
