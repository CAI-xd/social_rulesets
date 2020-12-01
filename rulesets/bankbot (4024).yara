/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: myusername
    Rule name: Bankbot
    Rule id: 4024
    Created at: 2018-01-19 12:04:39
    Updated at: 2018-01-23 10:03:17
    
    Rating: #0
    Total detections: 5
*/

rule BANKBOT : malware
{
	meta:
		date = "2018-01-19"

	strings:
		$a = {2f 70 72 69 76 61 74 65 2f 74 75 6b 5f 74 75 6b 2e 70 68 70}

	condition:
		all of them
}
