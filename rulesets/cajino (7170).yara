/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: liva
    Rule name: Cajino
    Rule id: 7170
    Created at: 2020-11-08 12:04:49
    Updated at: 2020-11-08 12:19:52
    
    Rating: #0
    Total detections: 0
*/

rule Cajino
{
	meta:
		description = "This rule detects Cajino spyware."

	strings:
		$location = ".getLastKnownLocation()"
		$deviceID = ".getDeviceId()"
		$record = "recorder.start()"
		$sms = "sendTextMessage"

	condition:
		$location and
		$deviceID and
		$record and
		$sms
}
