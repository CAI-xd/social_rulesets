/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: iconPackRu
    Rule id: 6873
    Created at: 2020-04-28 23:30:47
    Updated at: 2020-04-28 23:32:11
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule iconPackRu {

meta:
	description="This rule targets fake apps that are passed as icon packs"
	targetDomain="These apps communicate with the hardcoded domain spasskds.ru/update.php"
	md5="df30c7d28fbe5fc4f1e2778d104ec351"
	author="skeptre[@]gmail.com"
	filetype="apk/classes.dex"
	date="04/28/2020"
	

strings:
	$a1 = "aHR0cDovL3NwYXNza2RzLnJ1L3VwZGF0ZS5waHA="
	$a2 = "LmFwaw=="

	$b1 = "loadUrl"
	$b2 = "UpdateAPP"

condition:
	any of($a*) and any of($b*)

}
