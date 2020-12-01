/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dordy
    Rule name: Dordy_Clipper
    Rule id: 6798
    Created at: 2020-03-27 09:19:10
    Updated at: 2020-03-27 10:40:32
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Clipper : DordyRule
{
	meta:
		description = "This rule detects the Clipper apk, plese let me know how to get it better :] Just some student work"
		sample = "86507924e47908aded888026991cd03959d1c1b171f32c8cc3ce62c4c45374ef"

	//strings:
		//$packageName = "com.lemon.metamask"
		//$app_Name = "MetaMask"

	condition:
		androguard.certificate.sha1("6755834C9A93ADA415C0706A6EE036AF327CDD4D") and
		androguard.package_name("/com.lemon.metamask/") or
		androguard.app_name(/MetaMask/) and
		androguard.service("com.lemon.metamask.Util.ClipboardMonitorService") or
        androguard.service(/clipboard/) and 
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.url("api.telegram.org")
		
		
}
