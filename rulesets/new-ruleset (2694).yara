/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 2694
    Created at: 2017-05-16 11:17:48
    Updated at: 2018-03-27 07:43:07
    
    Rating: #0
    Total detections: 912
*/

import "androguard"

rule Fake_Flash_Player
{
  meta:
       description = "Detects fake flashplayer apps"
	   	   
	strings:
		$string_1 = "pay"
   condition:
	 $string_1 and
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) 
}
