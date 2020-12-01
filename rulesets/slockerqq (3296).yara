/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: pr3w
    Rule name: SLockerQQ
    Rule id: 3296
    Created at: 2017-08-02 12:42:41
    Updated at: 2017-08-02 12:46:02
    
    Rating: #0
    Total detections: 40
*/

import "androguard"

rule SLockerQQ
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/new-wannacry-mimicking-slocker-abuses-qq-services/"
		
	condition:
		androguard.package_name("com.android.admin.hongyan") or
		androguard.package_name("com.android.admin.huanmie") or
		androguard.app_name("TyProxy")
}
