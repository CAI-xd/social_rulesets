/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Virus_Policia
    Rule id: 841
    Created at: 2015-09-21 16:58:23
    Updated at: 2016-01-22 12:49:29
    
    Rating: #0
    Total detections: 8
*/

import "androguard"

rule BaDoink
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:
		$a = /asem\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/

	condition:
		$a
}
