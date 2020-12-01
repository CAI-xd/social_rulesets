/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: HeartBleed-CCS-OK.
    Rule id: 6217
    Created at: 2019-12-15 18:24:27
    Updated at: 2020-04-30 10:17:20
    
    Rating: #0
    Total detections: 273
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		/**
		 * Affected Versions:
		 * ------------------
		 * OpenSSL 1.0.1 through 1.0.1g
		 * OpenSSL 1.0.0 through 1.0.0l
		 * all versions before OpenSSL 0.9.8y   
		 */

	strings:
		$ = /OpenSSL 1\.0\.1[a-g]/
		$ = /OpenSSL 1\.0\.0[a-l]/
		$ = /OpenSSL 0\.9\.8[a-x]/

	condition:
		any of them
		
}
