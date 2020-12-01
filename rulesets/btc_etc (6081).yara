/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: koodous_test1
    Rule name: BTC_ETC
    Rule id: 6081
    Created at: 2019-11-03 10:17:23
    Updated at: 2020-07-27 14:41:42
    
    Rating: #0
    Total detections: 5
*/

rule koodous : BTC_ETH
{
	meta:
		description = "This rule detects bitcoin and ethereum"
		
	strings:
		$a = "/^(0x)?[0-9a-fA-F]{40}$/"
		$b = "/^(1|3)[a-zA-Z0-9]{24,33}$/"
		$c = "/^[^0OlI]{25,34}$/"
		
	condition:
		$a or ($b and $c)		
}
