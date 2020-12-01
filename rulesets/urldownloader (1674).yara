/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: UrlDownloader
    Rule id: 1674
    Created at: 2016-07-25 09:09:45
    Updated at: 2016-07-25 09:19:04
    
    Rating: #0
    Total detections: 458
*/

import "androguard"


rule UrlDownloader : Downloader
{
	condition:
		androguard.url(/stat\.siza\.ru/) or 
		androguard.url(/4poki\.ru/) or 
		androguard.url(/dating\-club\.mobie\.in/) or 
		androguard.url(/systems\.keo\.su/)
}
