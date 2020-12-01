/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cashlessconsumer
    Rule name: BillDesk Tracker
    Rule id: 5101
    Created at: 2018-12-05 06:21:05
    Updated at: 2018-12-13 08:16:02
    
    Rating: #0
    Total detections: 30
*/

import "androguard"

rule BillDeskPayActivity
{
	meta:
		description = "All BillDesk SDK Apps"
	condition:
		androguard.activity("com.billdesk.sdk.QuickPayView")		
}
