/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jackbox
    Rule name: Anubis
    Rule id: 6362
    Created at: 2020-02-07 08:35:04
    Updated at: 2020-10-30 11:40:45
    
    Rating: #0
    Total detections: 2
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
