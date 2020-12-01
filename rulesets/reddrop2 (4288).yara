/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: reddrop2
    Rule id: 4288
    Created at: 2018-03-22 21:50:38
    Updated at: 2018-03-24 00:34:46
    
    Rating: #0
    Total detections: 719
*/

import "androguard"
import "file"
import "cuckoo"


rule reddrop2
{
	meta:
		description = "This rule detects malicious samples belonging to Reddrop campaign"
		sample = "76b2188cbee80fffcc4e3c875e3c9d25"

	strings:
		$a_1 = "pay"
		$a_2 = "F88YUJ4"
		

	condition:
		all of ($a_*)

		
}
