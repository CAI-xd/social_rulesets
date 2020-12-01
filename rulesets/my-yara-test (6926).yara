/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chased
    Rule name: MY YARA TEST
    Rule id: 6926
    Created at: 2020-05-20 07:26:08
    Updated at: 2020-05-20 07:28:53
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This is apt BITTER"
	strings:
		 $a = "MainActivity===>"
    	$b = "KeepAliveJobService"
   	 	$c = "Hi, I am main here"
    	$d = "jobscheduler"

	condition:
		all of them
}
