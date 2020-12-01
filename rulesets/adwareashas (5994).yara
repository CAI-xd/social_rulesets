/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: photr
    Rule name: Adware.Ashas
    Rule id: 5994
    Created at: 2019-10-24 14:22:29
    Updated at: 2019-10-24 14:33:21
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Adware_Ashas
{
	meta:
		description = "Adware campaign on Google Play"
		url = "https://www.welivesecurity.com/2019/10/24/tracking-down-developer-android-adware/"
		sample = "c1c958afa12a4fceb595539c6d208e6b103415d7"

	strings:
		$a = "aHR0cDovLzM1LjE5OC4xOTcuMTE5OjgwODAvYWRzc2VydmVyLXYzL2NsaWVudF9jb25maWc="
		$f1 = "ALARM_SCHEDULE_MINUTES" fullword
		$f2 = "CODE_CLIENT_CONFIG" fullword
		$f3 = "FULL_ID" fullword
		$f4 = "intervalService" fullword

	condition:
		$a or all of ($f*)
}
