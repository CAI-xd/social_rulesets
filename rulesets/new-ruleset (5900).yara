/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: marcdiez
    Rule name: New Ruleset
    Rule id: 5900
    Created at: 2019-09-20 15:18:24
    Updated at: 2019-09-20 15:46:03
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Miners_cpuminer: coinminer

{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
		

	strings:
		
		$a1 = "MinerSDKRunnable"
		$a2 = "startMiner"
		$a3 = "stop_miner"
		$a4 = "cpuminer_start"
		
			
	condition:
		any of them and tag:detected
		
				
}

rule Miners_lib : coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
		

	strings:
		
		$a1 = "libcpuminer.so"
		$a2 = "libcpuminerpie.so"
			
	condition:
		$a1 or $a2 
		
				
}

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

rule Miner_a : coinminer

{

	meta:
		    description = "Coinhive"
			author = "https://koodous.com/analysts/JJRLR"

	strings:
	    $miner = "https://coinhive.com/lib/coinhive.min.js" nocase
	    $miner1 = "https://coin-hive.com/lib/coinhive.min.js" nocase
	    $miner2 = "new.CoinHive.Anonymous" nocase
	    $miner3 = "https://security.fblaster.com" nocase
	    $miner4 = "https://wwww.cryptonoter.com/processor.js" nocase
	    $miner5 = "https://jsecoin.com/server/api/" nocase
	    $miner6 = "https://digxmr.com/deepMiner.js" nocase
	    $miner7 = "https://www.freecontent.bid/FaSb.js" nocase
		$miner8 = "htps://authedmine.com/lib/authedmine.min.js" nocase
	    $miner9 = "https://www.bitcoinplus.com/js/miner.js" nocase
	    $miner10 = "https://www.monkeyminer.net" nocase

	condition:
	    any of them 
}



rule miner_adb
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
		author = "https://koodous.com/analysts/skeptre"

	strings:
		$a_1 = "/data/local/tmp/droidbot"
		$aa_1 = "pool.monero.hashvault.pro:5555"
		$aa_2 = "pool.minexmr.com:7777"
					
	condition:
		$a_1 and 
		any of ($aa_*)
						
}

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
