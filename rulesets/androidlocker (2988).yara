/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kenken
    Rule name: Android.Locker
    Rule id: 2988
    Created at: 2017-06-14 10:07:48
    Updated at: 2017-06-14 10:15:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

 

	condition:
		androguard.package_name("com.h.M")  
 

		
}
