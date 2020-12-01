/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Ludovic
    Rule name: Target_Bank_DB
    Rule id: 2652
    Created at: 2017-05-05 14:26:44
    Updated at: 2017-05-05 14:28:43
    
    Rating: #0
    Total detections: 837
*/

import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_DB : official
{
	strings:
		$string_target_bank_db = "com.db.mm.deutschebank"
	condition:

	($string_target_bank_db)
}
