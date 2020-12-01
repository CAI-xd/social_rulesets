/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: w4lls1t0
    Rule name: SanitasRule
    Rule id: 5303
    Created at: 2019-02-22 09:54:54
    Updated at: 2019-02-22 10:06:37
    
    Rating: #0
    Total detections: 88
*/

import "androguard"
import "file"
import "cuckoo"


rule string_sanitas
{
	meta:
		description = "Regla creada por Victor"

	strings:
	
		$string_1 = /sanitas\.es/
		$string_2 = /sanitas/
		

	condition:
		1 of ($string_*)
	
}
