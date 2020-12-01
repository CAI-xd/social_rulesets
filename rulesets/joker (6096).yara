/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: efec
    Rule name: Joker
    Rule id: 6096
    Created at: 2019-11-11 05:48:01
    Updated at: 2019-11-11 05:48:08
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule android_joker {     
    strings:
        $c = { 52656D6F746520436C6F616B } // Remote Cloak
        $cerr = { 6E6574776F726B2069737375653A20747279206C61746572 } // network issue: try later
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=
        $ip = { 332E3132322E3134332E3236 } // 3.122.143.26     
    condition:
        ($c and $cerr) or $net or $ip 
}
