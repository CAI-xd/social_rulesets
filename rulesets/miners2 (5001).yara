/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: Miners2
    Rule id: 5001
    Created at: 2018-10-19 12:13:27
    Updated at: 2018-10-19 12:13:45
    
    Rating: #0
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule Miners_lib : coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
		

	strings:
		
		$a1 = "libcpuminer.so"
		$a2 = "libcpuminerpie.so"
			
	condition:
		$a1 or $a2
		
				
}
