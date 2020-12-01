/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: xxf8xx
    Rule name: New Ruleset
    Rule id: 5138
    Created at: 2018-12-13 01:48:45
    Updated at: 2018-12-13 01:49:27
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule evernote
{

	strings:
		$a = co.tmobi.com.evernote.android.job.JobRescheduleService

}
