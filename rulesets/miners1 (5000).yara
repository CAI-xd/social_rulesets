/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: Miners1
    Rule id: 5000
    Created at: 2018-10-19 12:12:22
    Updated at: 2018-10-19 12:13:08
    
    Rating: #0
    Total detections: 35
*/

import "androguard"
import "file"
import "cuckoo"


rule Miners_cpuminer: coinminer

{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
		

	strings:
		
		$a1 = "MinerSDKRunnable"
		$a2 = "startMiner"
		$a3 = "stop_miner"
		$a4 = "cpuminer_start"
		
			
	condition:
		any of them
		
				
}
