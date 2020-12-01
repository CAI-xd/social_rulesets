/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: orenkor
    Rule name: ISIS mrat
    Rule id: 1007
    Created at: 2015-11-10 09:54:02
    Updated at: 2017-10-31 07:04:40
    
    Rating: #0
    Total detections: 4
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "8907e44c44753482ca1dd346c8282ae546a554c210dd576a3b1b467c25994c0a"

	strings:
	  $mrat_domain = "fdddt.pw"


	condition:
		$mrat_domain
		
}
