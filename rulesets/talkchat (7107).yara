/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jackbox
    Rule name: talkChat
    Rule id: 7107
    Created at: 2020-10-30 10:03:28
    Updated at: 2020-10-30 10:05:17
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects weird permission"


	condition:
		androguard.permission(/com.im.im.qingliao.push.permission.MESSAGE/)
		
}
