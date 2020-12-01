/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ransombleed
    Rule name: New Ruleset
    Rule id: 4876
    Created at: 2018-09-10 05:47:15
    Updated at: 2018-09-10 05:47:19
    
    Rating: #0
    Total detections: 0
*/

rule BitcoinAddress
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
    condition:
        any of them
}
