/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zyrik
    Rule name: mnrs3_regexp_based
    Rule id: 5230
    Created at: 2019-01-29 13:23:44
    Updated at: 2019-01-29 13:42:35
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule miners_regex : miner
{
	meta:
		description = "This rule detects miners application by a regex"
		author = "https://koodous.com/analysts/zyrik"

	strings:
		$regex001 = /(stratum\+tcp\:\/\/)?(([a-z0-9]*)\.)?(marketgid|(crypt(o|a)-?(loot|miningfarm|noter|\.csgocpu))|traviilo|butcalve|clgserv|50million|freshrefresher|(hide\.ovh)|jurtym?|pzoifaum|besti|mepirtedic|(gustaver\.ddns)|(jq(r?cdn|assets|errycdn|www))|adless|myeffect|nexttime|etzbnfuigipwvs|(worker\.salon)|cfcnet|bowithow|aalbbh84|ctlrnwbv|altavista|berateveng|jscdndel|mhiobjnirs|tidafors|((web)?(miner?)?(\.)?(sushi|litecoin|multi|webminer|ent|nimiq|space|graft|beep)?pool(er|s)?(\.hws|\.etn)?)|(never\.ovh)|chainblock|((coin-?(hive|have)-?)(s|r|rs|proxy|manager)?)|ethtrader|(open-?hive-?server(-?[0-9]{1,})?)|appelamule|scaleway|ppoi|(abc\.pema)|biberukalap|projectpoi|((jse?|bit|groestl|lite|cloud|plex|best)?coin(huntr|erra|nebula|lab|imp|pirate|signals|-?services?|pot|rail|-?cube|miningonline|blind)?)|(host\.d\-ns)|vidto|(eth-?pocket)|adzjzewsma|andlache|aymcsx|renhertfo|anyfiles|1q2w3|buyguard|kanke365|cloudflane|(mfio\.cf)|mine.torrent|(flare-?analytics)|monerise|terethat|hegrinhar|cnhv|encoding|megabanners|sparnove|(([a-z]{2,}cdn[0-9]{1,}|m(i|o)nero-?proxy-?[0-9]{2,})\.now)|bewaslac|papoto|((video\.)?(streaming\.)?estream)|willacrit|witthethim|nathetsof|ininmacerad|streambeam|kedtise|jsccnn|bhzejltg|depttake|adplusplus|hemnes|datasecu|netflare|flophous|noblock|ffinwwfpqi|baiduccdn1|reservedoffers|moneone|bablace|(oei1\.gq)|(wordc\.ga)|(mwor\.gq)|(aeros[0-9]{2,})|((support\.)?2giga\.(download|link))|([a-z]{2,}cdn[0-9]{1,}\.herokuapp)|rintindown|ermaseuc|wasm24|gridiogrid|cpufan|electroneum|verresof|jquery-cdn|evengparme|kdmkauchahynhrs|akgpr|(stratum\.bitcoin)|bjorksta|cfcdist|freecontent|hatcalter|sparechange|inwemo|xvideosharingeucsoft|uoldid|((crypto-?)?(wp-?)?(jscoin-?)?(light|ad-?|(authed)?(web)?|rex|app|support|(n|a)f|(m(o|i))?(n|h)(ero|key)|z|bro(wser)?|eth\.)?-?(miner?o?s?|xmr)(cripts|\.nablabee|\.nahnoji|pool|\.mining|\.nanopool|\.mobeleader|\.pr0gramm?|mytraffic|\.cryptobara|\.torrent|\.terorie|ad|-?(deu-)?[0-9]{1,2})?|\.beeppool)|((web)?-?(xmr)?-?(swift)?-?(coin)?-?(not)?-?mining(online)?)|blockchained|ledinund)\.[a-z]*/

	condition:
		androguard.permission(/android.permission.INTERNET/) and $regex001
		
}
