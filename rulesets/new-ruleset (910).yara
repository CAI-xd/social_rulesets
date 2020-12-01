/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: New Ruleset
    Rule id: 910
    Created at: 2015-10-09 21:20:55
    Updated at: 2015-10-09 21:23:03
    
    Rating: #0
    Total detections: 14105
*/

import "androguard"



rule adw
{
	meta:
		description = "adware"
		
	strings:
		// $a = "zv.play.jsp?al_id=4802&vd_id="
		$b = "http://a1.adchitu.com/ct"
		$c = "http://a1.zhaitu.info/zt/"


	condition:
		$b and $c
}
