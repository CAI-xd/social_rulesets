/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: JJRLR
    Rule name: ReadAlert2.0
    Rule id: 4030
    Created at: 2018-01-22 16:56:41
    Updated at: 2019-01-30 09:29:20
    
    Rating: #0
    Total detections: 349
*/

import "androguard"

rule redalert2

{
	meta:
		description = "RedAlert2.0"
		family = "Red Alert"


	condition:
	
		(androguard.url(/:7878/) or androguard.url(/:6280/)) or
		(androguard.service("westr.USSDService") and androguard.service("westr.service_rvetdi5xh.MessageBltService_df3jhtrgft43") and  androguard.service("westr.service_rvetdi5xh.WldService_dfgvgfd") and
		androguard.service("westr.service_rvetdi5xh.McdxService_efv3web")) or androguard.url("https://ttwitter.com/")


			
}
