/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: The_new_researcher
    Rule name: New Ruleset
    Rule id: 6974
    Created at: 2020-06-19 07:29:38
    Updated at: 2020-06-19 07:33:44
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules 	potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "debuggerpattern__rdtsc" 
		$b = "ft_jar" 
		$c = "ft_zip"
		$d = "zip_file" 
		$e = "debuggerpattern__cpuid"

	condition:
		 $a and $b and $c and $d and $e //Yes, we use crashlytics to debug our app!
		
}
