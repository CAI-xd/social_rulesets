/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Ginp
    Rule id: 6123
    Created at: 2019-11-24 01:59:58
    Updated at: 2019-11-24 02:24:41
    
    Rating: #0
    Total detections: 154
*/

import "androguard"
import "file"
import "cuckoo"


rule Ginp
{
	meta:
		description = "This rule detects Ginp Android malware"
		
	strings:
		$a1 = "IncomingSmsListener"
		$a2 = "PingToServerAndSendSMSService"
		$b1 = "HtmlLoader"
		
	condition:
		any of ($a*) or any of ($b*)
		
}
