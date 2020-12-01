/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: register
    Rule name: dianping_lp_rate
    Rule id: 6441
    Created at: 2020-03-03 15:34:47
    Updated at: 2020-06-16 02:59:23
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"

	strings:
		$a = "FIN_ GIFT"

	condition:
		$a		
}
