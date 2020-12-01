/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Faketoken
    Rule id: 2055
    Created at: 2016-12-30 08:17:02
    Updated at: 2016-12-30 09:01:46
    
    Rating: #0
    Total detections: 0
*/

import "file"
rule Faketoken : Test {
	meta: 
		description = "Ruleset to detect faketoken malware"
	
	condition:
		network.hosts = "185.48.56.239"
		

}
