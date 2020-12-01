/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: annafelicia
    Rule name: New Ruleset
    Rule id: 7128
    Created at: 2020-11-03 10:09:44
    Updated at: 2020-11-04 11:35:24
    
    Rating: #1
    Total detections: 0
*/

import "androguard"
import "file"

rule NoobHost 
{
	meta:
		Author= "Anna and Felicia"
		email = "s1958410@vuw.leidenuniv.nl"
		reference= "https://koodous.com/apks/c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		sample = "c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		date = "03/11/2020"
		description = "This is a basic YARA rule for CEO fraud."

	strings:
		$a = "_mips.so"
		$b = "jiagu"
		$c = "jiagu_x86"
		$d = "mips"
		$e = "_a64.so"
		$f = "https://t.me/POLICEryn2"

	condition:
		($a or $b or $c or $d or $e or $f) or
		androguard.package_name("noob.yt.team") or
	  	androguard.certificate.sha1("66ebe8f6a719790a2194c34b1f1bfb8df344f870")

}
