/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skyriver
    Rule name: New Ruleset
    Rule id: 5289
    Created at: 2019-02-19 02:03:26
    Updated at: 2019-04-15 10:06:06
    
    Rating: #0
    Total detections: 0
*/

import "androguard"



rule myest
{


	condition:
		androguard.receiver("com.android.license.CheckLicense") or androguard.service("com.android.license.LicenseService")
}
