/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: thatqier
    Rule name: videogames
    Rule id: 6152
    Created at: 2019-11-29 06:06:24
    Updated at: 2020-02-11 18:08:31
    
    Rating: #1
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : BankBot
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = "https://securify.nl/blog/SFY20170401/banking_malware_in_google_play_targeting_many_new_apps.html"
	
	strings:
		$c2_1 = "/private/tuk_tuk.php" nocase
		$c2_2 = "/private/add_log.php" nocase
		$c2_3 = "/private/set_data.php" nocase
		$c2_4 = "activity_inj" nocase
		
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}
