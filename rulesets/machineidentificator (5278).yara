/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: machineidentificator
    Rule id: 5278
    Created at: 2019-02-14 17:12:03
    Updated at: 2019-02-14 17:12:31
    
    Rating: #0
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "gas machineidentificator"

	strings:
		$a = "machineidentificator"

	condition:
		$a
}
