/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: miner3
    Rule id: 5004
    Created at: 2018-10-19 12:20:42
    Updated at: 2018-10-19 12:20:46
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"



rule miner_adb
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
		author = "https://koodous.com/analysts/skeptre"

	strings:
		$a_1 = "/data/local/tmp/droidbot"
		$aa_1 = "pool.monero.hashvault.pro:5555"
		$aa_2 = "pool.minexmr.com:7777"
					
	condition:
		$a_1 and 
		any of ($aa_*)
						
}
