/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reox
    Rule name: Cloned F-Droid
    Rule id: 4691
    Created at: 2018-07-26 05:57:04
    Updated at: 2018-07-26 06:14:08
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule clonedfdroid : pua
{
	meta:
		description = "Find cloned F-Droid Apps"
		sample = "5962770b87a51fe9198ffdece47ca6faafad98e162275bb485833381774a29cd"
		sample = "8ed89b20367d4ff0b375451d314780709cb706c17cc7103e9072ebf8ef2564d4"
	condition:
		(
			androguard.package_name("org.fdroid.fdroie") 
			or
			androguard.package_name("org.fdroid.fdroid")
		)
		and
		(
			androguard.activity(/com\.applisto\.appcloner\.classes.*/)
			or
			androguard.permission(/com.applisto.appcloner.permission.DEFAULT/)
		)
		
}
