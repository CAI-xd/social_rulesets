/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: casualdoge
    Rule name: Users Symbols Lite ruleset
    Rule id: 7317
    Created at: 2020-11-15 16:26:03
    Updated at: 2020-11-15 16:35:26
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects apps similar to Users Symbols Lite"
		sample = "4637ee04fe271ef3e893d7cc8738a9dac37dced328ae5e665e405781e069665f"

	strings:
		$a = "dalvik/annotation/EnclosingClass"

	condition:
		androguard.app_name("Users Symbol") or 
		(
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) 
		)or
		file.md5("296F1AF43380BE4790537D1ACA3434E7") and
		$a
		
}
