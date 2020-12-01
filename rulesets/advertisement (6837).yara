/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: bryans50
    Rule name: Advertisement
    Rule id: 6837
    Created at: 2020-04-08 19:00:46
    Updated at: 2020-04-08 19:05:50
    
    Rating: #0
    Total detections: 2233
*/

import "androguard"
import "file"

rule Advertisement {
	meta:
		description = "Yara rule to detect adware api calls within apps"
		rulePurpose = "Exersice"

	strings:
		$a = "ad"
		$b = "ads"	
		$c = "Advertising"
		$d = "millenialmedia"
		$e = "airpush"
		$f = "apperhand"

	condition:
		$a or 
		$b or 
		($c and $d and $e and $f) or (		
			androguard.permission(/ACCESS_NETWORK_STATE/) and
			androguard.permission(/INTERNET/) and
			androguard.permission(/WRITE_EXTERNAL_STORAGE/)) or
		androguard.certificate.sha1("b254ecc73bbc4107e7f6046f3138364fc2f94f07")
}
