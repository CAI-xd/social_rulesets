/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: banker_Dew18
    Rule id: 5099
    Created at: 2018-12-04 23:26:35
    Updated at: 2018-12-05 03:37:55
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule banker_Dew18
{
	meta:
		description = "Detects DewExample related samples"
		md5 = "510ed33e1e6488ae21a31827faad74e6"
		
		
	strings:
		$a_1 = "com.example.dew18.myapplication.MyService"
		$a_2 = "com.ktcs.whowho"
		$a_3 = "KEY_OUTGOING_REPLACE_NUMBER"
		$a_4 = "MEDIA_SCANNER_SCAN_FILE"

	
	condition:
		all of ($a_*)
 			    
				
}
