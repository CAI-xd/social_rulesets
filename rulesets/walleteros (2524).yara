/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: walleteros
    Rule id: 2524
    Created at: 2017-04-22 10:32:14
    Updated at: 2017-04-24 22:37:47
    
    Rating: #0
    Total detections: 440
*/

import "androguard"
import "file"
import "cuckoo"


rule walleteros
{
	meta:
		description = "Detects Bitcoin wallet.dat manipulation"

	strings:
		$a = "wallet.dat"

	condition:
		$a
		
}
