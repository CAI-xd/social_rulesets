/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: AadhaarSMSTracker
    Rule id: 5793
    Created at: 2019-07-30 11:19:53
    Updated at: 2019-07-31 12:30:05
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "droidbox"

rule AadhaarSMSTracker
{
	meta:
		description = "This rule detects apps using Aadhaar SMS"
	strings:
		$a = "GVID"
		$b = "RVID"
		$c = "GETOTP"		
	condition:
		($a or $b or $c) and
		droidbox.sendsms("1947") and
		androguard.permission(/android.permission.SEND_SMS/)
}
