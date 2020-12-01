/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: knian888
    Rule name: App1 ruleset
    Rule id: 7215
    Created at: 2020-11-09 20:26:23
    Updated at: 2020-11-09 21:41:45
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Media_Player : official
{
	meta:
		description = "This rule detects the Media Player application, hoping to stop other malware like it"
		sample = "026ebdbc5cb2f6bd33705b9342231961"

	condition:
		androguard.package_name("com.BestGame.StickmanOnlineWarriors3") and
		cuckoo.network.dns_lookup(/drius.aefrant.com/)
		
}
