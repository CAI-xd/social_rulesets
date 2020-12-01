/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: m3rkd45
    Rule name: New Ruleset
    Rule id: 1936
    Created at: 2016-10-27 14:14:50
    Updated at: 2016-10-27 14:15:48
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule wormHole
{
	meta:
		description = "Wormhome vulnerability found in com.qihoo.secstore con GPlay. After app launch, a SimpleWebServer service is called listening to 0.0.0.0:38517. It uses yunpan to upload files and get a 360 domain. App protected by proguard."
	strings:
