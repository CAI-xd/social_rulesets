/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wager47769
    Rule name: BlackRock test
    Rule id: 7003
    Created at: 2020-07-17 13:02:55
    Updated at: 2020-07-17 13:16:38
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule BlackRock
{
	meta:
		description = "This rule detects the BlackRock malware"
		sample = "81fda9ff99aec1b6f7b328652e330d304fb18ee74e0dbd0b759acb24e7523d8c"
		src = "https://www.threatfabric.com/blogs/blackrock_the_trojan_that_wanted_to_get_them_all.html"

	condition:
		androguard.app_name("Google Update") and 
		androguard.receiver(/Smsmnd.MmsReceiver/i) and
		androguard.receiver(/Admins/i) and
		androguard.receiver(/AlarmBroadcastReceiver/i)
}
