/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jim
    Rule name: FakeGoogleUpdate
    Rule id: 6986
    Created at: 2020-06-29 22:02:15
    Updated at: 2020-07-26 13:21:51
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule FakeGoogleUpdate
{
	meta:
		description = "Detects Fake Google Update Apps"

	condition:
		androguard.app_name("Google Update") 
		
}
