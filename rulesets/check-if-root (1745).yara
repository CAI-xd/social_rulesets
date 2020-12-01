/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: check if root
    Rule id: 1745
    Created at: 2016-08-16 10:18:46
    Updated at: 2016-08-16 10:19:43
    
    Rating: #0
    Total detections: 275184
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "identify samples that check if root"


	strings:
		$isroot = "uid=0"

	condition:
		$isroot
		
}
