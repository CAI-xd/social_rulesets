/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: SLocker
    Rule id: 669
    Created at: 2015-07-08 03:11:30
    Updated at: 2015-08-06 15:20:52
    
    Rating: #0
    Total detections: 22
*/

rule slocker_a
{
	meta:
		description = "SLocker.A"

	strings:
		$a = "StartLockServiceAtBootReceiver"
		$b = "148.251.154.104"
		
	condition:
		$a or $b
		
}
