/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: Porn Player Ransomware
    Rule id: 753
    Created at: 2015-08-04 09:45:38
    Updated at: 2015-08-06 15:21:00
    
    Rating: #0
    Total detections: 105
*/

rule pornplayer
{
	meta:
		description = "Porn Player, de.smarts.hysteric"

	strings:
		$a = "WLL.RSA"
		
	condition:
		$a
		
}
