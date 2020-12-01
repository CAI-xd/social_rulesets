/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Adware.CopyCat
    Rule id: 5726
    Created at: 2019-07-11 02:46:42
    Updated at: 2019-07-11 12:40:39
    
    Rating: #1
    Total detections: 2
*/

import "androguard"


rule CopyCat : adware
{
	meta:
		description = "Detects domains used by the CopyCat adware"
		source = "https://www.checkpoint.com/downloads/resources/copycat-research-report.pdf"

	strings:
		$a1 = /.mostatus.net/i
		$a2 = /.mobisummer.com/i
		$a3 = /.clickmsummer.com/i
		$a4 = /.hummercenter.com/i
		$a5 = /.tracksummer.com/i


	condition:
		any of them or (
		androguard.url(/.mostatus.net/i) or
		androguard.url(/.mobisummer.com/i) or
		androguard.url(/.clicksummer.com/i) or
		androguard.url(/.hummercenter.com/i) or
		androguard.url(/.tracksummer.com/i)
		)
}
