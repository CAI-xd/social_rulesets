/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Load2ing
    Rule name: Fake livechat app. (phishing app in Korea)
    Rule id: 4167
    Created at: 2018-02-06 00:54:04
    Updated at: 2019-05-30 01:06:06
    
    Rating: #0
    Total detections: 24
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Korea Phishing app"
		
	condition:
		androguard.package_name("sakura.phonetransfer")		
		
}
