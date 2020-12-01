/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: gretel_ibingo_launcher3
    Rule id: 5438
    Created at: 2019-04-10 00:09:18
    Updated at: 2019-04-10 00:09:22
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule gretel_ibingo_launcher3
{
	meta:
		description = "com.ibingo.launcher3"
		sha = "7dda8481973cec79416c9aa94d2176bc"
		
		
	strings:
		$a_1 = "sdk.loveota.com" fullword
        $a_2 = "alter.sbingo.net.cn" fullword
      
		
        	
	condition:
		all of ($a_*)
}
