/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: zyrik
    Rule name: PotentialMiners
    Rule id: 4984
    Created at: 2018-10-13 15:08:05
    Updated at: 2018-10-13 15:21:20
    
    Rating: #0
    Total detections: 1073
*/

import "androguard"
import "file"
import "cuckoo"


rule potential_miners_by_url : miner 
{
	meta:
		description = "This rule detects potential miners using urls"
		author = "https://koodous.com/analysts/zyrik"

	strings:
        $url1 = "coinhive.com"
        $url2 = "authedmine.com"
        $url3 = "minercry.pt"
        $url4 = "nfwebminer.com"
        $url5 = "load.jsecoin.com"
        $url6 = "webmine.cz"
        $url7 = "webmine.pro"
        $url8 = "www.coinimp.com"
        $url9 = "freecontent.stream"
        $url10 = "freecontent.data"
        $url11 = "freecontent.date"
        $url12 = "apin.monerise.com"
        $url13 = "minescripts.info"
        $url14 = "snipli.com"
        $url15 = "abc.pema.cl"
        $url16 = "metrika.ron.si"
        $url17 = "hallaert.online"
        $url18 = "st.kjli.fi "
        $url19 = "minr.pw"
        $url20 = "mepirtedic.com"
        $url21 = "weline.info"
        $url22 = "datasecu.download"
        $url23 = "cloudflane.com"
        $url24 = "hemnes.win"
        $url25 = "rand.com.ru"
        $url26 = "count.im"
        $url27 = "coinpot.co"
        $url28 = "gnrdomimplementation.com"
        $url29 = "metamedia.host"
        $url30 = "1q2w3.website"
        $url31 = "whysoserius.club"
        $url32 = "adless.io"
        $url33 = "moneromining.online"
        $url34 = "afminer.com"
        $url35 = "ajplugins.com"
        $url36 = "anisearch.ru"
        $url37 = "ulnawoyyzbljc.ru"
        $url38 = "mining.best"
        $url39 = "webxmr.com"
        $url40 = "cortacoin.com"
        $url41 = "jsminer.net"
        $url42 = "coinhive.min.js"
        $url43 = "load.jsecoin.com"
        $url44 = "minr.pw"
        $url45 = "st.kjli.fi"
        $url46 = "metrika.ron.si"
        $url47 = "cdn.rove.cl"
        $url48 = "host.d-ns.ga"
        $url49 = "static.hk.rs"
        $url50 = "hallaert.online"
        $url51 = "cnt.statistic.date"
        $url52 = "cdn.static-cnt.bid"
        $url53 = "coinimp.com"
        $url54 = "hashing.win"
        $url55 = "projectpoi.min"
        $url56 = "afminer.com"
        $url57 = "papoto.com"
        $url58 = "papoto.js"
        $url59 = "miner.php"
		
		
	condition:
		androguard.permission(/android.permission.INTERNET/) and 
		(any of them)
		
}
