/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: khiro
    Rule name: SimpleLocker B Tor
    Rule id: 732
    Created at: 2015-07-22 10:23:47
    Updated at: 2015-08-06 15:20:59
    
    Rating: #0
    Total detections: 5
*/

rule simplelocker_b_tor
{
	meta:
		description = "SimpleLocker.B Tor enabled"

	strings:
		$a = "1372587162_chto-takoe-root-prava.jpg"
		$b = "libtor.so"
		
	condition:
		$a and $b
}
