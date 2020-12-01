/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Alexx
    Rule name: New Ruleset
    Rule id: 6459
    Created at: 2020-03-09 13:28:09
    Updated at: 2020-03-09 13:29:44
    
    Rating: #0
    Total detections: 0
*/

rule Adware
{
	meta:
        description = Adware indicators
	strings:
    	$1 = ""
    	$2 = "&airpush_url="
		$3 = "getAirpushAppId"
		$4 = "Airpush SDK is disabled"
