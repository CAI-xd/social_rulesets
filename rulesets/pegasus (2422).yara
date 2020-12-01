/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pham
    Rule name: pegasus
    Rule id: 2422
    Created at: 2017-04-05 09:01:56
    Updated at: 2017-04-05 09:02:26
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "pegasus"
	strings:
		$a = "coldboot_init"
		$b = "/csk"

	condition:
		$a and $b
		
}
