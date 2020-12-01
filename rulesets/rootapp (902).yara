/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: RootApp
    Rule id: 902
    Created at: 2015-10-08 20:39:01
    Updated at: 2015-10-08 20:39:15
    
    Rating: #0
    Total detections: 385
*/

rule RootApp
{
	meta:
		description = "Root app"
		
	strings:
		$a = "ROOT_ERROR_FAILED"
		$b = "STEP_EXECUTE"
	
	condition:
		all of them
}
