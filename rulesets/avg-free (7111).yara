/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: s2669668
    Rule name: AVG FREE
    Rule id: 7111
    Created at: 2020-11-02 10:23:15
    Updated at: 2020-11-02 11:03:40
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule AVG_free
{
	meta:
		description = "This rule detects the AVG free version malware"
		sample = "0ed6f99dadb9df5354f219875bf268c3e1d5dbee9a4754bb1b2c7026aa37ce93"

	condition:
		androguard.package_name("com.applecakerecipes.QueenStudio") or
		androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.certificate.sha1("1e1b347f62f980e4eea6051d85c203a1eeeff1a8")
}
