/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: idp2
    Rule name: SimpLocker
    Rule id: 7267
    Created at: 2020-11-12 12:17:00
    Updated at: 2020-11-12 12:18:34
    
    Rating: #0
    Total detections: 0
*/

rule find_SimpLocker
{
	meta:
		authors = "Igor and Elize"
		date = "13 November"
		description = "This is a YARA rule to find SimpLocker"
		
	strings: 
		$a = "org/simplocker/MainService.java"
		$b = "org/simplocker/MainService$4.java"
		$c = "org/simplocker/TorSender.java"
		$d = "org/simplocker/HttpSender.java"
		$e = "org/simplocker/FilesEncryptor.java"
		$f = "org/simplocker/AesCrypt.java"
		$g = "org/simplocker/Constants.java"
		
	condition:
		($a and $b and $c and $d and $e and $f and $g)
}
