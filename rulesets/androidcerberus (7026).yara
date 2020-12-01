/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chaochaoxiong
    Rule name: Android.Cerberus
    Rule id: 7026
    Created at: 2020-08-11 16:07:29
    Updated at: 2020-08-11 16:08:50
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Android.Cerberus"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		  $a = "grabbing_google_authenticator2"
        $b = "run_app"
        $c = "change_url_connect"
        $d = "grabbing_pass_gmail"
        $d2 = "change_url_recover"
        $d3 = "send_mailing_sms"
        $d4 = "access_notifications"
        $d5 = "sms_mailing_phonebook"

	condition:
		all of them
		
}
