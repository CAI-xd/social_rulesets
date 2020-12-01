/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: BankingPhisher
    Rule id: 1217
    Created at: 2016-02-17 13:41:47
    Updated at: 2016-02-17 13:48:42
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

rule BankingPhisher : string
{
	meta:
		description = "This rule detects APKs in BankingPhisher Malware"
		sample = "8f53d3abc301b4fbb7c83865ffda2f1152d5e347"

	strings:
		$string_1 = "installed.xml"
		$string_2 = "testgate.php"
		
	condition:
		$string_1 or $string_2
}
