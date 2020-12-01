/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Adware.Leadbolt
    Rule id: 5739
    Created at: 2019-07-11 23:18:47
    Updated at: 2019-07-13 14:59:12
    
    Rating: #0
    Total detections: 64
*/

import "androguard"



rule Leadbolt : ads
{
	meta:
		description = "Detects leadbolt ad urls"


	condition:
		androguard.url(/ad.leadbolt\.net/) or
		androguard.url(/ad.leadboltapps\.net/) or
		androguard.url(/ad.leadboltmobile\.net/)
		
}
