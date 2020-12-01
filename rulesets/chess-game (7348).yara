/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: imnublet
    Rule name: Chess game
    Rule id: 7348
    Created at: 2020-11-17 09:48:44
    Updated at: 2020-11-18 09:33:21
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects whether an app is malicious"

	strings:

		$a = "HttpClient;->execute" //Query for a remote server
		$connect_to_url =  "java/net/URL;->openConnection" //connect to an URL
		$developer = "com.atrilliongames" //The package of the developer of the app
		
		
		

	condition:
		$a and $connect_to_url and $developer and androguard.permission(/android.permission.RECORD_AUDIO/) //If an game permission to record your audio and it wants to connect to a remote server, then it's most likely an malicious app.
}
