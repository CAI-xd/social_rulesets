/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Rubobi
    Rule id: 603
    Created at: 2015-06-17 15:23:32
    Updated at: 2015-08-06 15:20:19
    
    Rating: #0
    Total detections: 5130
*/

import "androguard"


rule koodous : official
{
	meta:
		description = "Rubobi"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "surprise"
		$b = "r/6UyV_i"

	condition:

		$a and $b and androguard.permission(/android.permission.SEND_SMS/)

		
}
