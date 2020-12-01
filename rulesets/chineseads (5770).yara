/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: TheSecurityDev
    Rule name: ChineseAds
    Rule id: 5770
    Created at: 2019-07-18 17:59:16
    Updated at: 2020-02-26 18:35:29
    
    Rating: #1
    Total detections: 982
*/

// Detects a lot of Chinese apps with Adware

import "cuckoo"


// https://cybernews.com/security/popular-camera-apps-steal-data-infect-malware/
rule aliyuncs: generic
{
	meta:
		description = "Try to detect Aliyunics related apps."
	
	strings:
		$url = /\.aliyuncs\.com/ nocase  // Privacy policy links use this
	
	condition:
		$url

}



rule ijoysoft
{
	meta:
		description = "Detect ijoysoft ad library"
		
	strings:
		$name = /ijoysoft/
		
		
		// Some strings.
		$a1 = "REMOTE IS NULL or PARCEL IS NULL !!!"
		$a2 = /you donot call with\(\) before/
		$a3 = "CREATE TABLE IF NOT EXISTS gift (_id INTEGER PRIMARY KEY AUTOINCREMENT,_index INTEGER DEFAULT 0,package TEXT UNIQUE NOT NULL, title TEXT, details TEXT, icon TEXT, url TEXT, poster TEXT, clicked INTEGER DEFAULT 0, submitted INTEGER DEFAULT 0, r_count INTEGER DEFAULT 0, d_count INTEGER DEFAULT 0, l_count INTEGER DEFAULT 0, version text )"
		
	
	condition:
		$name or any of ($a*)

}
