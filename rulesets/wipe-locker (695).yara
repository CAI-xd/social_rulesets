/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: Wipe Locker
    Rule id: 695
    Created at: 2015-07-15 03:58:47
    Updated at: 2015-08-06 15:20:54
    
    Rating: #0
    Total detections: 115
*/

rule wipelocker_a
{
	meta:
		description = "WipeLocker.A"

	strings:
		$a = "Elite has hacked you.Obey or be hacked"
		
	condition:
		$a
}
