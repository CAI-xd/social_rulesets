/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: spalomaresg
    Rule name: Ransomware
    Rule id: 3609
    Created at: 2017-09-19 13:44:29
    Updated at: 2017-10-24 07:21:05
    
    Rating: #0
    Total detections: 12
*/

rule Ransomware
{
	strings:
		$a = "All your files are encrypted"
		$b = "Your phone is locked until payment"

	condition:
		$a or $b	
}
