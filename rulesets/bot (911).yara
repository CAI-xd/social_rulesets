/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Bot
    Rule id: 911
    Created at: 2015-10-09 21:54:11
    Updated at: 2015-10-09 21:58:05
    
    Rating: #0
    Total detections: 988763
*/

rule Bot
{
	strings:
		$a = "/dodownload" ascii wide
		$b = "/dodelete" ascii wide
		$c = "/doupload" ascii wide
		$d = "/doprogress" ascii wide

	condition:
		all of them
}

rule Bot2
{
	strings:
		$a = "/download" ascii wide
		$b = "/delete" ascii wide
		$c = "/upload" ascii wide

	condition:
		all of them
}
