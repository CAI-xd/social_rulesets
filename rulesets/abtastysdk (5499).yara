/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jawz101
    Rule name: ABTastySDK
    Rule id: 5499
    Created at: 2019-04-30 23:10:16
    Updated at: 2019-05-01 04:41:36
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule ABTastySDK
{
	meta:
		description = "This rule detects ABTasty SDK"

	strings:
		$a = "com.abtasty."

	condition:
		$a or androguard.activity(/com.abtasty.*/)
		}
