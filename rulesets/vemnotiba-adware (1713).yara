/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Vemnotiba Adware
    Rule id: 1713
    Created at: 2016-08-02 07:36:23
    Updated at: 2020-05-02 13:01:11
    
    Rating: #-1
    Total detections: 5
*/

import "cuckoo"

rule Vemnotiba:Adware
{
	meta:
		description = "Android.Spy.305.origin WIP"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"

	/*strings:
		$a = "com.nativemob.client.cloudmessage.CloudMessageService"*/

	condition:
		cuckoo.network.dns_lookup(/client\.api-restlet\.com/) and
		cuckoo.network.dns_lookup(/cloud\.api-restlet\.com/)
}
