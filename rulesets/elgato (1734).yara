/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: ElGato
    Rule id: 1734
    Created at: 2016-08-10 07:54:06
    Updated at: 2017-11-15 03:07:27
    
    Rating: #0
    Total detections: 1638
*/

import "androguard"
import "file"
import "cuckoo"


rule ElGato : Ransom
{
	meta:
		description = "https://blogs.mcafee.com/mcafee-labs/cat-loving-mobile-ransomware-operates-control-panel/"
		
  strings:
        $text_string = "MyDifficultPassw"
		$text_2 = "EncExc"

    condition:
       $text_string or $text_2
 }
