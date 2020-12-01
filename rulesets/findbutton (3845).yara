/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: findbutton
    Rule id: 3845
    Created at: 2017-11-27 02:53:53
    Updated at: 2017-11-28 03:34:25
    
    Rating: #0
    Total detections: 109
*/

import "androguard"
import "file"
import "cuckoo"

/*
jsdk/sd.action
	www.lemonmobi.com
	www.woomobi.com
	www.ub7o.com
	
in/processurl20170405.js
	www.ub7o.com
*/
rule findbutton
{
	condition:
		cuckoo.network.dns_lookup(/www.ub7o.com/) or
		cuckoo.network.dns_lookup(/www.lemonmobi.com/) or
		cuckoo.network.dns_lookup(/www.woomobi.com/)	or
		cuckoo.network.dns_lookup(/new.havefunonyourphone.com/) or 
		cuckoo.network.dns_lookup(/api.jsian.com/) or
		cuckoo.network.dns_lookup(/igbli.com/) or
		cuckoo.network.dns_lookup(/api.jesgoo.com/) or
		cuckoo.network.dns_lookup(/api.moogos.com/) or
		cuckoo.network.dns_lookup(/api.smallkoo.com/) or
		cuckoo.network.dns_lookup(/cdn.jesgoo.com/)
}
