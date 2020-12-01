/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: secauvr2
    Rule name: fake gas localiza
    Rule id: 5279
    Created at: 2019-02-14 17:27:34
    Updated at: 2019-02-14 17:33:09
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "fake gas lokaliza"

	strings:
		$a = "starofertashd"
		$b = "heart.php?id="
		$c = "msg=king"

	condition:
		$a or $b or $c
}
