/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: riffraff
    Rule name: MobileSpy
    Rule id: 6880
    Created at: 2020-04-30 10:43:22
    Updated at: 2020-04-30 14:52:37
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"

rule MobileSpy : simple
{
	meta:
		description = "This rule should detect old Mobilespy from 2014"
		sample = "954ac28ac07847085e8721708e3373a62d5e9c97b19976820f2eba3161131997"

	condition:
		file.sha256("954ac28ac07847085e8721708e3373a62d5e9c97b19976820f2eba3161131997") or
	 	androguard.package_name("com.retina.smileyweb.ui") or
		androguard.certificate.sha1("ADDCAD719274B94AE233E33F5923D6B9BB78A417B34B851527A0B857A616A2E4")

		
}
