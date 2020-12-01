/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: vaibhav8
    Rule name: New Ruleset
    Rule id: 7084
    Created at: 2020-10-08 10:37:38
    Updated at: 2020-10-08 10:43:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Developers_with_known_malicious_apps
{
	meta:
		description = "This rule lists app from developers with a history of malicious apps"
		sample = "b1"

	strings:
	
		//$a = "Londatiga"
		//$b = "evaaee3ge3aqg"
		//$c = "gc game"
		//$d = "jagcomputersecuitity"
		//$e = "aaron balder"
	condition:
		(androguard.certificate.Md5("62DCF5128907311EA3FA0BF78FB6B25E")) or
		(androguard.certificate.sha1("1CA6B5C6D289C3CCA9F9CC0E0F616FBBE4E0573B")) or
		($b and androguard.certificate.sha1("79981C39859BFAC4CDF3998E7BE26148B8D94197")) or
		($c and androguard.certificate.sha1("CA763A4F5650A5B685EF07FF31587FA090F005DD")) or
		($d and androguard.certificate.sha1("4CC79D06E0FE6B0E35E5B4C0CB4F5A61EEE4E2B8")) or
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) 
		
}
