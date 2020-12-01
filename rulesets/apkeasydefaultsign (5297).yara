/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: ApkeasyDefaultSign
    Rule id: 5297
    Created at: 2019-02-19 23:11:58
    Updated at: 2019-03-20 12:20:22
    
    Rating: #1
    Total detections: 6512
*/

import "androguard"

rule apkeasy_tool  : repack
{
	meta:
		description = "apkeasy tool deafaulr sert for compiling source code"

condition:
        androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") or
		androguard.certificate.sha1("0C2440C055C753A8F0493B4E602D3EA0096B1023") or
		androguard.certificate.sha1("485900563D272C46AE118605A47419AC09CA8C11")

		
	
		
		}
