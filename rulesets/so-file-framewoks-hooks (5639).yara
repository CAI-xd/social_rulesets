/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: so file framewoks Hooks
    Rule id: 5639
    Created at: 2019-06-21 15:36:22
    Updated at: 2019-06-23 02:31:19
    
    Rating: #0
    Total detections: 0
*/

import "droidbox"
import "file"


rule addhook : addhook_nativ_so
{
		

	condition:
		file.md5("ec8e936a53d7a94a86a75af0b38db543")

		
}
