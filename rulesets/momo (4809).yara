/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Mehran
    Rule name: Momo
    Rule id: 4809
    Created at: 2018-08-13 15:21:42
    Updated at: 2018-08-13 15:37:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Momo
{
	condition:
		androguard.package_name("com.mobo.gram") and
		androguard.activity(/StepTwoActivityForce/i)
}
