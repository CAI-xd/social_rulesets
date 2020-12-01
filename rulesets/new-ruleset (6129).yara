/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dovinator
    Rule name: New Ruleset
    Rule id: 6129
    Created at: 2019-11-26 09:54:12
    Updated at: 2019-12-04 07:53:31
    
    Rating: #0
    Total detections: 0
*/

import "androguard"



rule adwind 
{
	meta:
		description = "This rule detects effected applications by adwind"
		
		strings: 
		
		$a = "load/stub.adwind"
		$b = "plugins/AdwindServer.classPK"
		$c = "plugins/AdwindServer.classuS]w"
		
		condition:
		
		all of them
}
