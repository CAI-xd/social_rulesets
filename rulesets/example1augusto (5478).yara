/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ds56xy
    Rule name: Example1Augusto
    Rule id: 5478
    Created at: 2019-04-19 23:48:31
    Updated at: 2019-04-20 02:44:20
    
    Rating: #0
    Total detections: 6
*/

import "androguard"

rule Example: Malware
{
	meta:
		description = "This rule detects custom URL suspicious C&C"
		sample = ""
		author = "Augusto Morales"

	strings:
		$domain_1 = "adspot.tfgapps.com"
		$domain_2 = "subscriptions-verifier.tfgapps.com"
		$domain_3 = "https://adspot.tfgapps.com/webview/"
		$ip_1 = "52.72.88.181" ascii wide
		$ip_2 = "34.227.145.183" ascii wide


	condition:
		any of ($domain_*) or any of ($ip_*)
}
