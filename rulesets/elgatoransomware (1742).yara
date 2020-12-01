/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: elGatoRansomware
    Rule id: 1742
    Created at: 2016-08-15 06:49:03
    Updated at: 2016-08-15 06:59:16
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$pass = "MyDifficultPassw"
		$exec = "EncExc"
	
	condition:
		$pass and $exec
	
		
}
