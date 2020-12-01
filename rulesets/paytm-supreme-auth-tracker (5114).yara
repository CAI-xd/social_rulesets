/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: PayTM Supreme Auth Tracker
    Rule id: 5114
    Created at: 2018-12-06 22:52:25
    Updated at: 2018-12-13 08:19:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule PayTMSupremeAuthActivity
{
	meta:
		description = "All PayTM auth Apps"
	condition:
		androguard.activity("com.one97.supreme.ui.auth.SupremeAuthActivity")
}
