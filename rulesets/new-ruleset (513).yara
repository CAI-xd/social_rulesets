/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bartolome
    Rule name: New Ruleset
    Rule id: 513
    Created at: 2015-05-26 08:37:15
    Updated at: 2015-08-06 15:45:27
    
    Rating: #0
    Total detections: 615439
*/

import "androguard"

rule otherFindSMS
{
    strings:
        $text_string = "sendsms"

    condition:
       ($text_string or androguard.permission(/SEND_SMS/))
	   and androguard.permission(/FLASHLIGHT/)
}
