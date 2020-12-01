/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: banking br generic
    Rule id: 5284
    Created at: 2019-02-14 22:02:10
    Updated at: 2019-02-17 18:48:56
    
    Rating: #0
    Total detections: 29
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "brazilian banks"

	strings:
		$a = "itaucard"
		$b = "bradesco"
		$c = "cef"
		$d = "saldo"
		$e = "uber"

	condition:
 		$a and $b and $c and $d and $e and
		androguard.permission(/android.permission.INTERNET/) 
		
}
