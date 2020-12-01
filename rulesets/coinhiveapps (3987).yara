/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: CoinhiveApps
    Rule id: 3987
    Created at: 2018-01-11 08:09:33
    Updated at: 2018-01-11 08:20:25
    
    Rating: #0
    Total detections: 77
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects coinhive Apps"

	strings:
		$coinhive = "https://coinhive.com/lib/coinhive.min.js"

	condition:
		androguard.permission(/android.permission.INTERNET/) and
		$coinhive 
}
