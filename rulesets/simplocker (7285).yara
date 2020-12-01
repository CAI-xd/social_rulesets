/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: UkkO
    Rule name: SimpLocker
    Rule id: 7285
    Created at: 2020-11-12 18:15:44
    Updated at: 2020-11-12 18:38:41
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule SimpLockerRansom
{
	meta:
		description = "This rule detects Ransomware similar to SimpLocker"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.package_name("org.simplelocker") and
		androguard.package_name("org.torproject")
		
		
}
