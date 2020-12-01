/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ppp1
    Rule name: New Ruleset
    Rule id: 7005
    Created at: 2020-07-20 13:35:15
    Updated at: 2020-07-20 13:37:13
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule ransomware_generic
{
	
	strings:
		$notice_1 = "All your files are encrypted" nocase
		$notice_2 = "Your phone is locked until paymenti" nocase
		$notice_3 = "your files have been encrypted!" nocase
		$notice_4 = "your Device has been locked" nocase
		$notice_5 = "All information listed below successfully uploaded on the FBI Cyber Crime Depar" nocase
		$notice_6 = "Your phone is locked , and all your personal data" nocase
	
	condition:
		1 of them	
}
