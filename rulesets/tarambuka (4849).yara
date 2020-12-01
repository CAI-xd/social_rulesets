/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: tarambuka
    Rule id: 4849
    Created at: 2018-08-24 23:56:17
    Updated at: 2018-08-28 19:44:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule tarambuka
{
	meta:
		description = "This rule detects tarambuka spyware"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"

	strings:
		$a_1 = "twtr.db"
		$a_2 = "hotml.db"
		$a_3 = "skdb.db"
		$a_4 = "vbrmsg.db"
		$a_5 = "whappdbcp.db"
		$a_6 = "MessageSenderService#oncreate"
		$a_7 = "MessageSenderTask#work"
		$a_8 = "PhoneCallSpyListener#sendRecording"
		$a_9 = "SystemAppManager#makeAppSystemApp"
		

		
	condition:
		all of ($a_*)
		
}
