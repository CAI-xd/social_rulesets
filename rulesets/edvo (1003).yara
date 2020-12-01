/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Alon9191
    Rule name: EDVO
    Rule id: 1003
    Created at: 2015-11-10 08:16:36
    Updated at: 2015-11-10 08:19:08
    
    Rating: #0
    Total detections: 61
*/

rule edvo
{

	strings:
		$a= "EDVO revision 0"

	condition:
		all of them
		
}
