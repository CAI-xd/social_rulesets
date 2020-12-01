/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Ali
    Rule id: 827
    Created at: 2015-09-14 13:47:34
    Updated at: 2015-11-04 16:54:31
    
    Rating: #0
    Total detections: 2772
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "packers"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "libmobisecy1"



	condition:
		$strings_b 
}
