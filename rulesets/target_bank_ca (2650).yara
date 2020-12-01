/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_Bank_CA
    Rule id: 2650
    Created at: 2017-05-05 14:13:44
    Updated at: 2017-05-05 14:15:53
    
    Rating: #0
    Total detections: 3848
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_CA : official
{
	strings:
		$string_target_bank_ca = "fr.creditagricole.androidapp"
	condition:

	($string_target_bank_ca)
}
