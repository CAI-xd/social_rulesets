/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: JJRLR
    Rule name: Miner
    Rule id: 4185
    Created at: 2018-02-08 11:24:16
    Updated at: 2018-09-05 06:48:18
    
    Rating: #0
    Total detections: 53
*/

rule miner : coinminer

{

	meta:
		    description = "Coinhive"

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
