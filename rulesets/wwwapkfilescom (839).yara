/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: www.apkfiles.com
    Rule id: 839
    Created at: 2015-09-21 16:43:01
    Updated at: 2017-12-26 12:58:45
    
    Rating: #0
    Total detections: 1523
*/

import "androguard"



rule apkfiles : official
{
	meta:
		description = "Accede a un repositorio de apks"

	condition:
		androguard.url(/www\.apkfiles\.com/)
}
