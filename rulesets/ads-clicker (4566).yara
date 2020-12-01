/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: ads-clicker
    Rule id: 4566
    Created at: 2018-06-22 07:08:57
    Updated at: 2018-06-22 07:29:00
    
    Rating: #0
    Total detections: 0
*/

import "cuckoo"


rule adclicker
{
    meta:
        description = "https://www.riskiq.com/blog/interesting-crawls/battery-saving-mobile-scam-app/?utm_source=twitter&utm_medium=social-media&utm_campaign=ad-clicking-scam-app&utm_content=blog"


    condition:

        cuckoo.network.dns_lookup(/aerowizard.me/) or
        cuckoo.network.dns_lookup(/virgintraffic.xyz/) or
        cuckoo.network.dns_lookup(/luxurytraffic.me/) or
        cuckoo.network.dns_lookup(/bosstrack.xyz/) or
        cuckoo.network.dns_lookup(/postbackmylove.xyz/) or
        cuckoo.network.dns_lookup(/releasetraf.xyz/) or
        cuckoo.network.dns_lookup(/yeahguru.me/) or
        cuckoo.network.dns_lookup(/iamtomato.xyz/) or
        cuckoo.network.dns_lookup(/knossos.xyz/) or
        cuckoo.network.dns_lookup(/mediapostback.xyz/) or
        cuckoo.network.dns_lookup(/conversioncap.xyz/) or
        cuckoo.network.dns_lookup(/exo-click.xyz/) or
        cuckoo.network.dns_lookup(/trafficreach.xyz/) or
        cuckoo.network.dns_lookup(/trackthisurl.xyz/) or
        cuckoo.network.dns_lookup(/visitidtrk.xyz/) or
        cuckoo.network.dns_lookup(/focusrates.xyz/) or
        cuckoo.network.dns_lookup(/shopgroup.xyz/) or
        cuckoo.network.dns_lookup(/cashplugin.xyz/) or
        cuckoo.network.dns_lookup(/secretdroid.xyz/) or
        cuckoo.network.dns_lookup(/newyearpage.xyz/) or
        cuckoo.network.dns_lookup(/moneroxmr.xyz/) or
        cuckoo.network.dns_lookup(/moonleaders.me/) or
        cuckoo.network.dns_lookup(/rocketdrive.me/) or
        cuckoo.network.dns_lookup(/callthepiggy.xyz/) or
		cuckoo.network.dns_lookup(/109.169.85.117/) or
		cuckoo.network.dns_lookup(/109.169.85.119/) or
		cuckoo.network.dns_lookup(/109.169.87.58/)

}
