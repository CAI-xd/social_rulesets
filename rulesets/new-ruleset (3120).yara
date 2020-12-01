/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 3120
    Created at: 2017-07-12 09:00:24
    Updated at: 2017-07-13 07:09:49
    
    Rating: #0
    Total detections: 865
*/

import "androguard"

rule Fake_Flash_Player
{
  meta:
       description = "Detects fake flashplayer apps"
	   	   
	strings:
		$string_1 = "lock"
		$string_2 = "pay"
   condition:
	 $string_1 and $string_2 and
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) 
}
