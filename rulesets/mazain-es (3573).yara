/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xjustyx
    Rule name: Mazain ES
    Rule id: 3573
    Created at: 2017-09-12 09:56:41
    Updated at: 2017-09-12 09:58:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

rule koodous : official
{
	meta:
		description = "This rule detects mazain application, used to show all Yara rules 						potential"
	
    strings:
        $str_1 = "com.bbva.bbvacontigo"
		$str_2 = "com.bbva.bbvawalletmx"
		$str_3 = "com.bbva.netcash"

    condition:
        all of ($str_*)
}
