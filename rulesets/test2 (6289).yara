/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: sn81
    Rule name: test2
    Rule id: 6289
    Created at: 2020-01-09 18:20:44
    Updated at: 2020-01-13 11:52:49
    
    Rating: #0
    Total detections: 8
*/

import "androguard"
import "file"
import "cuckoo"


rule disruptive1
{
	meta:
		description = "searching for disruptive ads"
		//sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	
	strings:
		$a = /google-ads-admob/ nocase

	condition:
		(androguard.activity(/OnBackedPressed/i) or 	 androguard.activity(/doubleBackToExitPressedOnce/i)) and
		androguard.permission(/android.permission.INTERNET/) 
		and $a
		
		
}

rule disruptive2
{
	meta:
		description = "searching for disruptive ads"
		//sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a= "OnBackedPressed" nocase
		$b = "doubleBackToExitPressedOnce" nocase
		$c = /google-ads-admob/ nocase

	condition:
		androguard.permission(/android.permission.INTERNET/) and
		($a or $b) and
		$c
		
}
