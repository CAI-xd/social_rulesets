/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dloyens
    Rule name: Covid19withRansomware
    Rule id: 6827
    Created at: 2020-04-05 13:25:02
    Updated at: 2020-04-06 13:28:02
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "cuckoo"

rule covid19ransom
{
	meta:
		description = "This rule detects the Covid19 APK with Ransomware"
		sample = "6b74febe8a8cc8f4189eccc891bdfccebbc57580675af67b1b6f268f52adad9f"

	condition:
		androguard.package_name("com.device.security") or (
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		cuckoo.network.http_request(/https:\/\/qmjy6\.bemobtracks\.com\/go\/4286a004-62c6-43fb-a614-d90b58f133e5/)
		)
}
