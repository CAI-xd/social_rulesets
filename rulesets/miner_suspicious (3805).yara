/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: miner_suspicious
    Rule id: 3805
    Created at: 2017-11-03 20:18:23
    Updated at: 2017-12-20 04:21:34
    
    Rating: #0
    Total detections: 318
*/

import "androguard"
import "file"
import "cuckoo"


rule miner_suspicious
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"

	strings:
		$a_1 = "miner.start()"
		$b_2 = "libcpuminer.so"
		$b_3 = "libcpuminerpie.so"
			
	condition:
		$a_1 or any of ($b_*)
		
				
}
