/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: New Ruleset
    Rule id: 3868
    Created at: 2017-12-04 15:47:01
    Updated at: 2017-12-04 15:54:12
    
    Rating: #0
    Total detections: 306603
*/

import "androguard"
import "file"
import "cuckoo"


rule MalignantFeatures : jcarneiro
{
	meta:
		description = "This rule detects applications containing any of the following list of potential malignant features"
	
	strings:
		$a = "2.5.8"
    	$b = "10308"
    	$c = "2.3.7"
    	$d = "2.7.3"
    	$e = "Diego Batt"
    	$j = "2.4.7"
    	$k = "2.7.7"
    	$l = "2.1.8"
    	$m = "2.7.5"
	    $n = "2.7.8"
    	$o = "2.8.8"
    	$p = "2.8.5"
    	$q = "2.2.8"
    	$r = "2.8.7"
    	$s = "2.5.5"
    	$t = "2.6.3"

	condition:
		any of them
		
}
