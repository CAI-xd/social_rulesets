/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pIrasa
    Rule name: Exobot
    Rule id: 5040
    Created at: 2018-11-06 09:24:25
    Updated at: 2018-11-06 09:25:38
    
    Rating: #0
    Total detections: 18
*/

import "androguard"
import "file"
import "cuckoo"


rule Anubis : abc
{
	meta:
		description = "Exobot"

	condition:
		
		androguard.receiver(/AlarmRcv/) and
		androguard.receiver(/BootRcv/)

		

}
