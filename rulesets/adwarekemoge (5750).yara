/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Adware.Kemoge
    Rule id: 5750
    Created at: 2019-07-12 19:41:52
    Updated at: 2019-07-12 20:14:39
    
    Rating: #0
    Total detections: 1
*/

import "androguard"


rule Kemoge : Adware Rooter
{
	meta:
		description = "Tries to detect Kemoge adware, based on the C&C url"

	strings:
		$a = /kemoge\.net/

	condition:
		any of them or androguard.url(/kemoge\.net/)
		
}
