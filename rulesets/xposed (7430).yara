/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: BartMichellekVqXd
    Rule name: xposed
    Rule id: 7430
    Created at: 2020-11-26 10:02:01
    Updated at: 2020-11-27 09:56:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule xposed_1: xposed
{

	meta:
		description = "xposed"
		sample = "25093f6d4e9e73ecf9c83f635722ea84117f56b6a673a72d0bc6529b24768553"

	strings:
		$a = "assets/xposed_init" //rule_1
		
	condition:
		$a
		
}
