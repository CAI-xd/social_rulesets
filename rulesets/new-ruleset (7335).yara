/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Lucasall
    Rule name: New Ruleset
    Rule id: 7335
    Created at: 2020-11-16 15:21:23
    Updated at: 2020-11-16 15:22:00
    
    Rating: #1
    Total detections: 0
*/

import "androguard"

rule Minecraft
{

	meta:
		description = "A rule to detect malicious Minecraft APKS. Minecraft should not do anything with SMSes and should not need phone information such as boot completed. It should also not do https requests and access elemnts of the page."
		sample = "35bb105bd203c0677466d2e26e71a28ba106f09db3a7b995e796825f5f0e1908"
	
	strings:
		$js_class = /getElement(sByClassName | ByID )/
		$click = "click()"

	condition:
		androguard.app_name(/Minecraft/) and (
		$js_class or $click or
		androguard.url("https://api.onesignal.com/") or
		androguard.permissions(/android.permission.READ_SMS/) or
		androguard.permissions(/android.permission.SEND_SMS/) or
		androguard.permissions(/android.permission.RECEIVE_SMS/) or
		androguard.permissions(/android.permission.WRITE_SMS/) or
		androguard.permissions(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permissions(/android.permission.READ_PHONE_STATE/) or
		androguard.permissions(/android.permission.USER_PRESENT/) or
		androguard.activity(/\.sms\./)
		)

}