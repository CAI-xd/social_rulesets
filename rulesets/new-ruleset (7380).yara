/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: marTrein
    Rule name: New Ruleset
    Rule id: 7380
    Created at: 2020-11-17 21:01:52
    Updated at: 2020-11-18 11:57:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule findSample : similar
{
	meta:
		Author = "Martijn Combe - s2599406, Alano Kling - s2486725"
		description = "This rule detects files similar to our apk sample"
		sample = "1e9fbd7f097f6fd62091c68033035a94009ab069e5d5a7b31bdc19d3ffd6d223"

	condition:
		// Check if the package name is the same
        androguard.package_name("com.couponapp2.chain.tac04010") and
        
        // Check dangerous permissions
        androguard.permission(/android.permission.BLUETOOTH/) and 
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.GET_TASKS/) and
        androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.READ_PHONE_STATE/) and
        
        androguard.url(/koodous\.com/) and
        
        // Compare the certificate
        androguard.certificate.sha1("434d119a04d7ec39ec4e8d319d55010302f68722") and 
        
        // Make sure we don't find the same hash
        not file.md5("b594258ab0e98db9c49b18f36dc5b601") and 
        
        cuckoo.network.dns_lookup(/settings.crashlytics.com/)
}
