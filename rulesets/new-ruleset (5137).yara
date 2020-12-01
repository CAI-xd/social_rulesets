/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xxf8xx
    Rule name: New Ruleset
    Rule id: 5137
    Created at: 2018-12-12 23:05:41
    Updated at: 2018-12-13 01:50:05
    
    Rating: #0
    Total detections: 3381
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	strings:
		$ai = "com.google.android.gms.ads.InterstitialAd"
		$b = "co.tmobi.com.evernote.android.job.JobRescheduleService"

	condition:
		1 of them
}
