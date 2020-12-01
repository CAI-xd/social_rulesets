/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: PerikiyoXD
    Rule name: ElfEqual_MobileOffers
    Rule id: 6275
    Created at: 2020-01-04 04:29:06
    Updated at: 2020-01-12 06:30:28
    
    Rating: #1
    Total detections: 1720
*/

rule ElfEqual_MobileOffers
{
	meta:
		description = "A 'MobileOffers' app"
		sample = "7f2dbed572155425fbaae8d2bdfc5bad5e16a2e7a4e3698b486505e9954dc6ab"
		sample = "C1870A8AFF2FB4EEDCAE2C3CB091F75A7046343A8F472F3F6B5AC07D1382925D"
		sample_url = "https://mobileoffers-br-download.com/830/171?file=TeamSpeak%203%20v3.3.2%20Apk%20Paid%20Full"
		sample_url_description = "Must use an Android User-Agent, otherwise you'll be redirected to Google Play."
	strings:
		$ = "x0"
		$ = "x1"
		$ = { 7f 45 4c 46 3d }
	condition:
		all of them	
}
