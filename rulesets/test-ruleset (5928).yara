/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: yleg
    Rule name: Test Ruleset
    Rule id: 5928
    Created at: 2019-10-02 14:42:48
    Updated at: 2019-10-03 13:20:01
    
    Rating: #0
    Total detections: 47027
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "First rule used to detect certain permissions"

	condition:
		androguard.permission(/android.permission.INTERNET/)
		
}
