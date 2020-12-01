/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: axelleap
    Rule name: Fake Wallet Apps
    Rule id: 5560
    Created at: 2019-05-24 13:46:48
    Updated at: 2019-05-24 13:48:59
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule fake_wallet_apps : official
{
	meta:
		description = "Detect fake wallet apps"
		sample = "f8c0f2d6cfd09c398465cfb913628f9dceaa850b49a2c9022dad7be0f931e81e"
		sample = "e81c3278f46f480ea3c0dda21b2781700ca438c6a4287d4746ba527134c6e71e"


	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.url(/coinwalletinc\.com/)
		
}
