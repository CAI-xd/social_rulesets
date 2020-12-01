/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: Trojan.Clipper
    Rule id: 5746
    Created at: 2019-07-12 15:53:30
    Updated at: 2019-07-12 16:01:17
    
    Rating: #0
    Total detections: 2
*/

rule Clipper
{
	meta:
		description = "Tries to detect the Clipper malware"

	strings:
		$a1 = "ClipboardMonitorService"
		$a2 = "ClipboardManager"
		$a3 = "clipboard-history.txt"

	condition:
		all of ($a*)
}
