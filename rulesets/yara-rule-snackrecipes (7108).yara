/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Merlijn
    Rule name: YARA rule SnackRecipes
    Rule id: 7108
    Created at: 2020-10-31 09:23:09
    Updated at: 2020-11-09 21:26:27
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"

rule Trojan : SnacksRecipes
{
	meta:
		description = "Trojan targeting mobile devices through the use of an application"
		sample = "7bd03a855da59f3a3255cf5c7535bc29"

	condition:
		androguard.package_name("com.androidgenieapps.snacksrecipes") and
		androguard.app_name("SnacksRecipes") and
        androguard.activity(/com.chownow.lemoncuisineofindia.sdk.activity.StartActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.GET_TASKS/)
}
