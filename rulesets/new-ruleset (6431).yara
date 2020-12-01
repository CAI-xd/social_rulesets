/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: endlif
    Rule name: New Ruleset
    Rule id: 6431
    Created at: 2020-02-28 11:07:09
    Updated at: 2020-02-28 11:07:20
    
    Rating: #0
    Total detections: 0
*/

rule TencentLocation : spy
{
	meta:
		description = "This rule detects apps which use Tencent location service, which may be spyware. Also, many apps which use this are suspicious Chinese apps"

	strings:
		$a1 = /addrdesp/i
		$a2 = /resp_json/i
