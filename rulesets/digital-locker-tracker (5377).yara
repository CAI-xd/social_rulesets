/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: Digital Locker Tracker
    Rule id: 5377
    Created at: 2019-03-28 11:48:25
    Updated at: 2019-03-28 11:49:20
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule DigitalLockerTracker
{
	meta:
		description = "This rule detects DigitalLocker SDK"
	strings:
		$a = "https://api.digitallocker.gov.in/"
		$b = "https://api.digitallocker.gov.in/public/oauth2/1/token"
		$c = "https://api.digitallocker.gov.in/public/oauth2/1/authorize"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
