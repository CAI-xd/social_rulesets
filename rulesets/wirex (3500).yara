/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rowland
    Rule name: WireX
    Rule id: 3500
    Created at: 2017-08-30 04:10:39
    Updated at: 2017-08-30 05:05:36
    
    Rating: #0
    Total detections: 11
*/

rule WireX
{
	meta:
        description = "Evidences of WireX."
		sample = "168624d9d9368155b7601e7e488e23ddf1cd0c8ed91a50406484d57d15ac7cc3"

	strings:
		$1 = "axclick.store"
		$2 = "snewxwri"
   	condition:
    	1 of them
}
