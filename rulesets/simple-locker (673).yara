/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: Simple Locker
    Rule id: 673
    Created at: 2015-07-08 08:40:00
    Updated at: 2015-08-06 15:20:52
    
    Rating: #1
    Total detections: 219
*/

rule simplelocker_a
{
	meta:
		description = "SimpleLocker.A"

	strings:
		$a = "fbi_btn_default"
		
	condition:
		$a
		
}
