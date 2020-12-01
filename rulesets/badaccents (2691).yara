/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: badaccents
    Rule id: 2691
    Created at: 2017-05-14 22:31:54
    Updated at: 2017-05-14 22:38:36
    
    Rating: #0
    Total detections: 16
*/

import "androguard"


rule badaccents
{
	meta:
		description = "This rule detects badaccents"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"



	condition:
		androguard.activity(/Badaccents/i) 
	
		
}
