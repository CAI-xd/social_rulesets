/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bryTesting
    Rule name: Xavier
    Rule id: 2635
    Created at: 2017-05-04 14:06:17
    Updated at: 2017-09-26 15:50:25
    
    Rating: #0
    Total detections: 4
*/

import "androguard"



rule Xavier
{
	meta:
		description = "Picks up samples with Xavier defined activity"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:

		androguard.activity(/xavier.lib.XavierActivity/i)

}
