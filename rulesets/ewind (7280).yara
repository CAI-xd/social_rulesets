/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: UkkO
    Rule name: Ewind
    Rule id: 7280
    Created at: 2020-11-12 16:10:15
    Updated at: 2020-11-12 16:19:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule EwindTrojan
{
	meta:
		description = "This rule detects an Ewind Trojan"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png"
		$b = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"

	condition:
		($a or $b) and
		androguard.package_name("com.gus.pizzapaxbielefeld") and
		androguard.permission(/android.permission.GET_TASKS/)
		
}
