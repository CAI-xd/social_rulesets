/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: csa_sven
    Rule name: MetaMaskClipper
    Rule id: 6834
    Created at: 2020-04-07 19:20:14
    Updated at: 2020-04-07 23:16:33
    
    Rating: #1
    Total detections: 51
*/

import "androguard"
import "file"

rule MetaMaskClipper {
	meta:
		description = "Detects association with the clipper used in the MetaMask impersonating trojan"
		rulePurpose = "Educational exercise"

	strings:
		$ethAddress = "0xfbbb2EF692B5101f16d3632f836461904C761965"
		$btcAddress = "17M66AG2uQ5YZLFEMKGpzbzh4F1EsFWkmA"	
		$methodName = "onPrimaryClipChanged"
		$setterName = "setPrimaryClip"		

	condition:
		$ethAddress or 
		$btcAddress or 
		($methodName and $setterName) or (
			androguard.app_name("MetaMask") and		
			androguard.permission(/ACCESS_NETWORK_STATE/) and
			androguard.permission(/INTERNET/) and
			androguard.permission(/WRITE_EXTERNAL_STORAGE/) and		
			androguard.url(/api\.telegram\.org/)) or
		androguard.certificate.sha1("14F52769440E01A4CEF3991FB081637CD10BDBB3")
}

//Commments are welcome
