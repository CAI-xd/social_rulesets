/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Cryopiggy
    Rule id: 6333
    Created at: 2020-01-30 13:12:30
    Updated at: 2020-01-30 13:12:34
    
    Rating: #0
    Total detections: 1539
*/

import "androguard"
import "file"
import "cuckoo"


rule adware_hide_ikon {
strings: 
$ = /Cryopiggy/
$ = /Cryopiggy/ nocase wide


condition:
1 of them
}
