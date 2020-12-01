/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: apitarresi
    Rule name: myrule1
    Rule id: 4836
    Created at: 2018-08-23 16:12:48
    Updated at: 2018-08-23 16:25:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

private global rule whatever2
{
	condition:
		androguard.app_name(/a/) or
		androguard.app_name(/b/) or
		androguard.app_name(/c/) or
		androguard.app_name("Materialize Your App")
}
