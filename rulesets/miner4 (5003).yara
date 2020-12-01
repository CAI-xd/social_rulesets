/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mmorenog
    Rule name: miner4
    Rule id: 5003
    Created at: 2018-10-19 12:16:20
    Updated at: 2018-10-19 12:16:26
    
    Rating: #0
    Total detections: 10
*/

import "androguard"
import "file"
import "cuckoo"

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
