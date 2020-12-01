/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nemo
    Rule name: Messai.in  | Twelfth Mile
    Rule id: 5799
    Created at: 2019-07-31 08:10:49
    Updated at: 2019-07-31 08:27:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule TwelfthMileDetect
{
	meta:
		description = "All apps using twelfthmile SDK (https://messai.in/) for Credit Scoring"
	strings:
		$a = "twelfthmile"
	condition:
		$a or 
		androguard.service("com.twelfthmile") or 
		androguard.receiver("com.twelfthmile")
}
