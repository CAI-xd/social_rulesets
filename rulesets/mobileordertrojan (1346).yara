/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: MobileOrder/Trojan
    Rule id: 1346
    Created at: 2016-04-15 12:06:52
    Updated at: 2016-04-15 12:23:34
    
    Rating: #1
    Total detections: 34160
*/

import "androguard"

rule MobileOrder
{
	meta:
		description = "MobileOrder trojan."
		sample = "https://analyst.koodous.com/apks/4ef62ee5732b9de3f59a3c94112b0e7c90f96763c6e4a447992c38bb94fdfcf9"

	strings:
		$key ="#a@u!t*o(n)a&v^i"
		$iv = "_a+m-a=p?a>p<s%3"
		$var = "&nmea=%.1f|%.1f&g_tp=%d"

	condition:
		all of them
		
}
