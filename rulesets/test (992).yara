/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Alon9191
    Rule name: Test
    Rule id: 992
    Created at: 2015-11-09 07:19:55
    Updated at: 2015-11-09 08:06:59
    
    Rating: #0
    Total detections: 2156
*/

import "androguard"
import "file"

rule testing
{
	meta:
		description = "This rule is a test"
		
	strings:
		$a = "install"

	condition:
		all of them
		// androguard.package_name("com.rwatch") or
		// file.sha256("2a5dc60ae66bf1d59399d5953ac122d860d0748af6a86286010bbe68a9818773")
		
}
