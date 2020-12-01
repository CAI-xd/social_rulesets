/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kpatsak
    Rule name: Execute superuser command
    Rule id: 2727
    Created at: 2017-05-21 09:33:34
    Updated at: 2017-06-20 21:39:21
    
    Rating: #0
    Total detections: 7976
*/

import "androguard"
import "file"
import "cuckoo"


rule SUexec
{
	meta:
		description = "Caution someone wants to execute a superuser command"
		

	strings:
		$a = "\"su\", \"-c\""
		$b ="su -c"

	condition:
		
		$a or $b		
}
