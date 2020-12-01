/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: doopel23
    Rule name: OmniRat Hunter
    Rule id: 5062
    Created at: 2018-11-16 09:16:42
    Updated at: 2018-11-16 09:16:58
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

rule Android_OmniRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects OmniRat"
		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"

	strings:
		$a = "android.engine.apk"
	condition:
		(androguard.activity(/com.app.MainActivity/i) and 
		 androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and 
		 androguard.package_name(/com.app/i)) and $a
}
