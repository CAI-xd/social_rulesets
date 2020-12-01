/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Disane
    Rule name: TruCallerSMSThief
    Rule id: 6833
    Created at: 2020-04-07 08:53:44
    Updated at: 2020-05-18 11:02:30
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"


rule TruCallerSMSThief
{
	meta:
		description = "This rule detects JS based TruCaller SMS Thief"
		sample = "4b7a8be741378ff56452909890fd3b82ccbee91917770064764f9df7f5bc4783"

	strings:
		$required_1 = "startHourlyTimerForSMS"

	condition:
		($required_1) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/)
}
