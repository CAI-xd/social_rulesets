/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: miner5
    Rule id: 5005
    Created at: 2018-10-19 12:21:03
    Updated at: 2018-10-19 12:21:07
    
    Rating: #0
    Total detections: 16
*/

import "androguard"
import "file"
import "cuckoo"


rule miner_b : coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
		
	strings:
		$a1 = "android-cpuminer/"
		$a2 = "mining.subscribe"
		$url1 = "https://coinhive.com/lib/coinhive.min.js" nocase
		$url2 = "https://coin-hive.com/lib/coinhive.min.js" nocase
		$url3 = "https://crypto-loot.com/lib/miner.min.js" nocase
		$url4 = "https://camillesanz.com/lib/status.js" nocase
		$url5 = "https://www.coinblind.com/lib/coinblind_beta.js" nocase
		$url6 = "http://jquerystatistics.org/update.js" nocase
		$url7 = "http://www.etacontent.com/js/mone.min.js" nocase
		$url8 = "https://cazala.github.io/coin-hive-proxy/client.js" nocase
		$url9 = "http://eruuludam.mn/web/coinhive.min.js" nocase
		$url10 = "http://www.playerhd2.pw/js/adsensebase.js" nocase

		
	
	condition:
		$a1 or $a2 or 1 of ($url*)	
}
