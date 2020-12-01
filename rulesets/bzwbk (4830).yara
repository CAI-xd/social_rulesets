/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: apitarresi
    Rule name: bzwbk
    Rule id: 4830
    Created at: 2018-08-23 14:25:48
    Updated at: 2018-08-23 17:05:49
    
    Rating: #0
    Total detections: 78
*/

import "androguard"
import "file"
import "cuckoo"


rule whatever
{
	meta:
		description = "This rule detects something"


	condition:
		androguard.app_name(/BZWBK/) or 
		androguard.app_name("BZWBK") or 
		androguard.app_name(/bzwbk/) or
		androguard.app_name("bzwbk") or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/bzwbk24/) or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name("BZWBK24 mobile") or
		androguard.app_name(/Santander/) or
		androguard.app_name("Santander")
	
		
}
