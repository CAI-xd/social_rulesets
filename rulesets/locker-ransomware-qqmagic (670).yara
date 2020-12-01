/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: Locker Ransomware (qqmagic)
    Rule id: 670
    Created at: 2015-07-08 03:12:10
    Updated at: 2015-08-06 15:20:52
    
    Rating: #1
    Total detections: 32200
*/

rule locker_a
{
	meta:
		description = "Locker.A"

	strings:
		$a = "qqmagic"
		
	condition:
		$a
		
}
