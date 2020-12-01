/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: GhostCtrl
    Rule id: 3190
    Created at: 2017-07-18 13:58:13
    Updated at: 2017-07-18 14:01:34
    
    Rating: #0
    Total detections: 12
*/

import "androguard"


rule GhostCtrl 
{
	meta:
		description = "This rule detects partially GhostCtrl campaign"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		report = "http://blog.trendmicro.com/trendlabs-security-intelligence/android-backdoor-ghostctrl-can-silently-record-your-audio-video-and-more/"

	
	condition:
		androguard.certificate.sha1("4BB2FAD80003219BABB5C7D30CC8C0DBE40C4D64")
	
		
}
