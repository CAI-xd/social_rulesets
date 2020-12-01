/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Banker
    Rule id: 710
    Created at: 2015-07-16 10:48:38
    Updated at: 2016-02-05 11:19:53
    
    Rating: #0
    Total detections: 101330
*/

import "androguard"

rule Banker : official
{
	meta:
		description = "This rule detects one variant of Banker malware"
		sample = "0665299A561BC25908BB79DA56077A93C27F1FE05988457DD8E9D342C246DD01"

	strings:
		$a = {67 6F 6F 67 6C 65 2F 73 63 63 2F 41 70 70 4D 61 69 6E}
		$b = {67 65 74 4C 69 6E 65 31 4E 75 6D 62 65 72} // getLine1Number
		$c = {73 65 6E 64 54 65 78 74 4D 65 73 73 61 67 65} // sendTextMessage

	condition:

		$a and $b and $c

		
}
