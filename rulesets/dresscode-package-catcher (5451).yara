/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reino
    Rule name: DressCode Package Catcher
    Rule id: 5451
    Created at: 2019-04-11 20:42:59
    Updated at: 2019-04-11 20:45:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Dresscode_hzytrfd : official
{
	meta:
		description = "This rule detects potential dresscode infections based on the hzytrfd package name"


	
	condition:
		androguard.package_name("hzytrfd") 
		
	
		
}
