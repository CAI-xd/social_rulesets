/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: davidT
    Rule name: Perm READ CLIPBOARD (Android Q)
    Rule id: 5805
    Created at: 2019-08-01 05:36:10
    Updated at: 2019-08-01 05:46:47
    
    Rating: #0
    Total detections: 19
*/

import "androguard"

rule permissions: readclipboard
{
	meta:
		description = "New permission in Android Q, such that apps need to declare if they're doing clipboard snarfing.."

	condition:
		androguard.permission(/android\.permission\.READ_CLIPBOARD_IN_BACKGROUND/)
}
