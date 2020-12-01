/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: maximilionis
    Rule name: SMS Trojan CybSec Assignment app1
    Rule id: 7173
    Created at: 2020-11-08 22:22:13
    Updated at: 2020-11-09 14:52:02
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Tojan: SMS
{
	meta:
		Authors = "M.Q. Romeijn & M. De Rooij"
		description = "The mentioned permissions in the YARA rule contain sensitive information from the user and should not be accessed by applications like a media player. These permissions together with a package name or application name that suggests a media player is possibly malicious. Adding to this, the mentioned receivers should be out of scope for a media player as well, since writing and receiving SMS messages is not something a media player should do."
		sample = "1d69234d74142dba192b53a7df13e42cd12aa01feb28369d22319b67a3e8c15a"

	strings:
		$a = "http://www.pv.com/pvns/"

	condition:
		(androguard.package_name("18042_Video_Player.apk") 
		or androguard.app_name("HD Video Player"))
		
		and
		
		(androguard.receiver(/excite.dolphin.strategy.bot.sms.ComposeSmsActivity/) 
		or androguard.receiver(/excite.dolphin.strategy.bot.sms.MmsReceiver/)) 
		
		and
		
		(androguard.permission(/android.permission.RECEIVE_SMS/) 
		or androguard.permission(/android.permission.WRITE_SMS/)
		or androguard.permission(/android.permission.READ_SMS/)
		or androguard.permission(/android.permission.SEND_SMS/)) 
		
		and 
		
		$a		
}
