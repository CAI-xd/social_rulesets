/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roskyfrosky
    Rule name: Banker Package_name
    Rule id: 1709
    Created at: 2016-08-01 07:53:11
    Updated at: 2017-10-18 05:42:01
    
    Rating: #1
    Total detections: 1454
*/

import "androguard"
import "file"
import "cuckoo"


rule package_name
{
	meta: 
		author = "https://twitter.com/roskyfrosky"
		description = "This rule detects all banker apps with specific package_names"
	condition:
		androguard.package_name("com.note.donote") or 
		androguard.package_name("cosmetiq.fl") or 
		androguard.package_name("com.glory") or
		androguard.package_name("org.slempo.service") or 
		androguard.package_name("com.construct") or 
		androguard.package_name("com.avito") or
		androguard.package_name("com.wood") or 
		androguard.package_name("ru.drink.lime") or 
		androguard.package_name("com.constre") or  	
		androguard.package_name("com.motion") or
		androguard.package_name("app.six") or
		androguard.package_name("com.example.street.two") or
		androguard.package_name("com.example.livemusay.myapplication")
		
}
