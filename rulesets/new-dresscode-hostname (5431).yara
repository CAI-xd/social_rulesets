/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reino
    Rule name: New DressCode (hostname)
    Rule id: 5431
    Created at: 2019-04-09 15:32:13
    Updated at: 2019-04-09 17:12:49
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule newdress : official
{
	meta:
		description = "This rule detects the Dresscode"


	strings:
		$a = "wun03_mrxhn_mvg"
	
	condition:
		$a 
		
		
		}
