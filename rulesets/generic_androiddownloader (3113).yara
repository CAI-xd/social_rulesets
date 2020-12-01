/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Anulabs
    Rule name: Generic_Android/Downloader
    Rule id: 3113
    Created at: 2017-07-11 12:54:15
    Updated at: 2018-08-24 09:12:22
    
    Rating: #1
    Total detections: 9052
*/

rule Downloader
{

    strings:
        $a = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.pngPK"
		$b = "file:///android_asset"
		$c = "market://"
		$d = "MKKSL/x}^<"

    condition:
        all of them
		}
