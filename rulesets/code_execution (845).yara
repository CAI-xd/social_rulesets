/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmanzanero
    Rule name: Code_Execution
    Rule id: 845
    Created at: 2015-09-21 17:47:12
    Updated at: 2015-09-21 18:44:45
    
    Rating: #0
    Total detections: 605804
*/

import "androguard"


rule Code_Execution : official
{
	meta:
		description = "Ejecucion de codigo"
		

	strings:
		$a = "java/lang/Runtime"
		$b = "exec"

	condition:
		$a and $b
		
}
