/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: myusername
    Rule name: Bankbot version
    Rule id: 4003
    Created at: 2018-01-18 08:55:58
    Updated at: 2018-01-23 10:02:47
    
    Rating: #0
    Total detections: 15
*/

rule BANKBOT_VERSION : malware
{
	meta:
		date = "2018-01-18"
		sample = "40ad2444b83f6a1c25dd153214a1a16bcaa2640ebaf7735d6f1ee2591989e58e"

	strings:
		$a1 = {2f 70 72 69 76 61 74 65 2f 63 68 65 63 6b 50 61 6e 65 6c 2e 70 68 70}
		$a2 = {2f 70 72 69 76 61 74 65 2f 74 75 6b 5f 74 75 6b 2e 70 68 70}

	condition:
		all of them
}
