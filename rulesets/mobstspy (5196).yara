/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: MOBSTSPY
    Rule id: 5196
    Created at: 2019-01-09 21:43:53
    Updated at: 2019-01-09 21:45:24
    
    Rating: #0
    Total detections: 1
*/

rule mobstspy
{
	meta:
		description = "#MOBSTSPY"
		sample = "32b5d73c3f88d07abb0527f44136dedf13c8d728d9ec37321b40246ffb272aa8"

	strings:
		$a = "moc.ppatratsibom.www//:ptth"

	condition:
		$a
}
