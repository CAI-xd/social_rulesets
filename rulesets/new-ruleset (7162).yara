/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TaroSpruijt
    Rule name: New Ruleset
    Rule id: 7162
    Created at: 2020-11-07 18:56:15
    Updated at: 2020-11-09 20:14:04
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects SimpLocker"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"

	strings:
		$a = "http://xeyocsu7fu2vjhxs.onion/"
		$b = "19" 
		$c = "DISABLE_LOCKER"
		$d = "FILES_WAS_ENCRYPTED"
		$e = "127.0.0.1"
		$f = "jndlasf074hr" 

	condition:
		androguard.app_name(/SimpLocker/) and
		androguard.activity(/BOOT_COMPLETED/) and
		androguard.activity(/TOR_SERVICE/) and
		androguard.activity(/MainService$3/) and
		androguard.activity(/MainService$4/) and
		androguard.activity(/MainService$5/) and
		all of them and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
		
}
