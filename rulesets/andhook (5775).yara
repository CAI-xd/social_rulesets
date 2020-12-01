/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: AndHook
    Rule id: 5775
    Created at: 2019-07-20 23:15:46
    Updated at: 2019-07-20 23:24:21
    
    Rating: #0
    Total detections: 427
*/

rule AndHooklib : hooker framework
{
	meta:
		description = "AndHook FrameWork"

	strings:
		$a = "AndHook"

	condition:
		$a
}

rule libprotectClass : packer
{
	meta:
		description = "AndHook Class"

	strings:
		$a = "AndHook"

	condition:
		$a
}
