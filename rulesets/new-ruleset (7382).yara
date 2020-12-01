/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Matador
    Rule name: New Ruleset
    Rule id: 7382
    Created at: 2020-11-17 21:35:29
    Updated at: 2020-11-18 12:31:13
    
    Rating: #0
    Total detections: 0
*/

rule koodous : official
{
	meta:
		authors = "Amr Adwan & Jingwen Liu"
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "7bc14c496a29bedbba6cad5a47d4c23f"

	strings:
		$a = "http://cdn.appnext.com/tools/services/4.7.1/config.json"
		$b = "http://imgs1.e-droid.net/android-app-creator/icos_secc/"
		$c = "https://facebook.com/device?user_code=%1$s&qr=1"

	condition:
		any of them
		
}
