/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: TencentLocationSDK (Possible Spyware)
    Rule id: 5732
    Created at: 2019-07-11 15:45:00
    Updated at: 2019-07-13 14:49:46
    
    Rating: #0
    Total detections: 237
*/

rule TencentLocation : spy
{
	meta:
		description = "This rule detects apps which use Tencent location service, which may be spyware. Also, many apps which use this are suspicious Chinese apps"

	strings:
		$a1 = /addrdesp/i
		$a2 = /resp_json/i

	condition:
		all of ($a*)
		
}
