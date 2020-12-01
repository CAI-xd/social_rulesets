/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: 5h1vang
    Rule name: Andr_Tordow.Bank.trojan
    Rule id: 1832
    Created at: 2016-09-21 07:19:42
    Updated at: 2016-09-29 07:34:02
    
    Rating: #4
    Total detections: 28
*/

import "androguard"


rule andr_tordow
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"

	condition:
		androguard.package_name("com.di2.two") or		
		(androguard.activity(/API2Service/i) and
		androguard.activity(/CryptoUtil/i) and
		androguard.activity(/Loader/i) and
		androguard.activity(/Logger/i) and 
		androguard.permission(/android.permission.INTERNET/)) or
		
		//Certificate check based on @stevenchan's comment
		androguard.certificate.sha1("78F162D2CC7366754649A806CF17080682FE538C") or
		androguard.certificate.sha1("BBA26351CE41ACBE5FA84C9CF331D768CEDD768F") or
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}
