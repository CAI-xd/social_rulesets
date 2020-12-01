/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: libshellx.so
    Rule id: 4888
    Created at: 2018-09-17 08:13:29
    Updated at: 2018-11-26 12:30:34
    
    Rating: #0
    Total detections: 8476
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "libshellx"

	strings:
		$a = "libshellx" nocase

	condition:
		$a
		
		
}
