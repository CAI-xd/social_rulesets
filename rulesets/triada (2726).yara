/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kpatsak
    Rule name: Triada
    Rule id: 2726
    Created at: 2017-05-21 09:23:31
    Updated at: 2017-05-21 12:57:47
    
    Rating: #0
    Total detections: 12471
*/

import "androguard"
import "file"
import "cuckoo"


rule TriadaDetector
{
	meta:
		description = "Detect Triada"
		

	strings:
		$a = "VF*D^W@#FGF"
		$b ="export LD_LIBRARY_PATH"

	condition:
		$a or $b
		
}
