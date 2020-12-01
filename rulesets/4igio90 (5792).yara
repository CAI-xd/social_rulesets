/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: 4igio90
    Rule id: 5792
    Created at: 2019-07-29 12:08:25
    Updated at: 2019-07-29 12:09:34
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "frida check"
		sample = ""

	strings:
	$a = { FC 6F BA A9 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 FF 0F 40 D1 FF 83 3A D1 F5 0F 40 91 B5 2A 06 91 F6 0B 40 91 }

	condition:
		all of them
		
}
