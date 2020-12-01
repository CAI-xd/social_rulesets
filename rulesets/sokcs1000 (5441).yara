/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reino
    Rule name: Sokcs1000
    Rule id: 5441
    Created at: 2019-04-10 12:18:17
    Updated at: 2019-04-15 09:17:02
    
    Rating: #0
    Total detections: 22
*/

import "androguard"
import "file"
import "cuckoo"




rule socks_1000 : official
{
	meta:
		 description = "This rule detects  Socks4 or Socks5"
		

	strings:
		$a = "Socks4"
		$b = "Socks5"

	condition:
	
		$a  or $b
		
		
}
