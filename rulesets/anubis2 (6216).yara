/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: EfeEdipCeylani
    Rule name: Anubis2
    Rule id: 6216
    Created at: 2019-12-15 17:27:34
    Updated at: 2019-12-15 17:27:40
    
    Rating: #0
    Total detections: 15
*/

import "androguard"
import "cuckoo"
import "droidbox"


rule anubis
{
	meta:
		description = "Trojan-Banker.AndroidOS.Anubis"
		
	condition:
		droidbox.written.data(/spamSMS/i) and
		droidbox.written.data(/indexSMSSPAM/i) and
		droidbox.written.data(/RequestINJ/i) and
		droidbox.written.data(/VNC_Start_NEW/i) and
		droidbox.written.data(/keylogger/i) 
		
}
