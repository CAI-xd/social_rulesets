/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: New Ruleset
    Rule id: 5002
    Created at: 2018-10-19 12:15:58
    Updated at: 2018-10-19 12:16:03
    
    Rating: #0
    Total detections: 6
*/

import "androguard"
import "file"
import "cuckoo"



rule Androidos_js : coinminer
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
		author = "https://koodous.com/analysts/pr3w"

	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"

	condition:
		$url and 1 of ($s*)	
}
