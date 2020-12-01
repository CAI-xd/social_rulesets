/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Fr4
    Rule name: BlackRock
    Rule id: 7006
    Created at: 2020-07-22 09:21:50
    Updated at: 2020-07-22 09:21:50
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Banker : BlackRock
{
	meta:
        description = "Trojan targeting Banks - BlackRock"
	
	strings:
		$c2_1 = "gate.php" nocase
		$c2_2 = "inj" nocase

		$string_1 = "imei" nocase
		$string_2 = "banks" nocase
		$string_3 = "AES" nocase

		$cmd_1 = "injActive" nocase
		$cmd_2 = "android_id" nocase
		$cmd_3 = "cardNumber" nocase
		
	condition:
		1 of ($c2_*)
		and 2 of ($string_*)
		and 2 of ($cmd_*)
		and (
			androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		)
}
