/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: starsWallpaper
    Rule id: 6373
    Created at: 2020-02-07 22:37:14
    Updated at: 2020-02-07 22:38:12
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule starsWallpaper_jan2020
{
	meta:
		description = "This rule detects Adware malware discussed in the blog below"
		blog = "https://www.evina.fr/a-malware-rises-to-the-top-applications-in-google-play-store/"
		
	strings:
		$a1 = "loadLibrary"
    	$a2 = "kkpf"
    	$a3 = "com.sstars.walls"

	condition:
        all of ($a*)

		
}
