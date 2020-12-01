/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Disable_KeyGuard
    Rule id: 843
    Created at: 2015-09-21 17:17:31
    Updated at: 2015-09-21 17:19:51
    
    Rating: #0
    Total detections: 117777
*/

import "androguard"



rule Posible_bypass_Screenlock
{
	meta:
		description = "Bypass_Screenlock"



	condition:
		
		androguard.permission(/android.permission.DISABLE_KEYGUARD/)
		
		
}
