/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roskyfrosky
    Rule name: SLocker_Ransomware
    Rule id: 3295
    Created at: 2017-08-02 09:31:48
    Updated at: 2017-08-04 09:35:29
    
    Rating: #0
    Total detections: 2099
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	strings:
		$a = "your files have been encrypted!"
		$b = "your Device has been locked"
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar"

	condition:
		$a or $b or $c or androguard.package_name("com.android.admin.huanmie") or androguard.package_name("com.android.admin.huanmie")
		
}
