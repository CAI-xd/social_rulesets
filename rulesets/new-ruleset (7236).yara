/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Roosj
    Rule name: New Ruleset
    Rule id: 7236
    Created at: 2020-11-10 10:17:04
    Updated at: 2020-11-10 10:36:57
    
    Rating: #0
    Total detections: 0
*/

rule Hack_game_candy
{
    meta:
        package_name = "com.hdc.bookmark189248"
		Author = "Lorensius W. L. T"
        email = "lorenz@londatiga.net"
        sample = "6ad5fa4ce0c0d92540c89580868da133"
        
    strings:
        $a = "http://mobileapp.url.ph"
        $b = "com.hdc.bookmark189248.MainActivity"
		$c = "com.hdc.bookmark189248.WebActivity"
		$d = "android.intent.category.LAUNCHER"
		$e = "android.intent.action.MAIN"

    condition:
        all of them
}
