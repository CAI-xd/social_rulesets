/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: colorfulsummer
    Rule name: New Ruleset
    Rule id: 6065
    Created at: 2019-11-01 06:51:21
    Updated at: 2020-05-13 08:42:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule hacking_team : stcert
{
	meta:
		description = "com.lody.virtual.client.stub.StubActivity"
		samples = "none"

	condition:
		androguard.activity("com.lody.virtual.client.stub.StubActivity*")

		
}
