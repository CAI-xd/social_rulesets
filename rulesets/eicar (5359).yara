/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nekmo
    Rule name: eicar
    Rule id: 5359
    Created at: 2019-03-15 09:10:46
    Updated at: 2019-03-15 09:14:29
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule eicar_substring_test {

    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"

    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        all of them
}
