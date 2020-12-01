/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: FBI Locker
    Rule id: 674
    Created at: 2015-07-08 09:22:08
    Updated at: 2015-08-06 15:20:52
    
    Rating: #2
    Total detections: 164
*/

rule fbilocker_a
{
	meta:
		description = "FBILocker.A"

	strings:
		$a = "74F6FD5001ED11E4A9DEFABADE999F7A"
		
	condition:
		$a
		
}
