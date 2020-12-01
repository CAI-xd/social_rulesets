/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: OverSeer
    Rule id: 1898
    Created at: 2016-10-09 15:35:22
    Updated at: 2018-06-17 12:14:07
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Android_OverSeer
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect OverSeer."
		references = "https://blog.lookout.com/embassy-spyware-google-play"
	condition:
		androguard.receiver(/test\.parse\.AlarmReceiver/i) and
		androguard.receiver(/test\.parse\.SenderReceiver/i) and
		androguard.receiver(/test\.parse\.NetworkReceiver/i) and
		androguard.filter(/dex\.SEND_ACTION/i)
}
