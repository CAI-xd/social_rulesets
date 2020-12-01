/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenk
    Rule name: certificates path rule
    Rule id: 1632
    Created at: 2016-07-15 14:10:11
    Updated at: 2016-07-15 14:13:49
    
    Rating: #0
    Total detections: 160019
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects sample that mess around with the sensitive system/priv-app path (for payload dropping etc)"


	strings:
		$certs_path = "etc/security/cacerts"

	condition:
		$certs_path
		
}
