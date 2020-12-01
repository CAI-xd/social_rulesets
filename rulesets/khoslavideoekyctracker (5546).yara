/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: KhoslaVideoeKYCTracker
    Rule id: 5546
    Created at: 2019-05-17 12:20:15
    Updated at: 2019-05-17 12:21:04
    
    Rating: #0
    Total detections: 6
*/

import "androguard"

rule KhoslaVideoeKYCTracker
{
	meta:
		description = "All Khosla Video eKYC SDK Apps"	
	condition:		
		androguard.activity("com.khoslalabs.videoidkyc.ui.init.VideoIdKycInitActivity")
}
