/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: PayTM SDK Tracker
    Rule id: 4966
    Created at: 2018-10-10 13:19:43
    Updated at: 2018-10-18 02:17:55
    
    Rating: #0
    Total detections: 795
*/

import "androguard"

rule PayTMActivity
{
	meta:
		description = "All PayTM SDK Apps"	

	condition:
		androguard.activity("com.paytm.pgsdk.PaytmPGActivity")		
		
}
