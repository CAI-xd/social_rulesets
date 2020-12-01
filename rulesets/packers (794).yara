/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Packers
    Rule id: 794
    Created at: 2015-08-25 18:37:28
    Updated at: 2015-08-26 18:41:06
    
    Rating: #0
    Total detections: 51016
*/

rule libAPKProtect : packer
{
	meta:
		description = "Packer libAPKProtect"

	strings:
		$a = "APKMainAPP"
		$b = "libAPKProtect"

	condition:
		any of them
}

rule libprotectClass : packer
{
	meta:
		description = "Packer libProtect"

	strings:
		$a = "libprotectClass"

	condition:
		$a
}
