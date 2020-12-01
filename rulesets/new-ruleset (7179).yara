/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: FlorisRick
    Rule name: New Ruleset
    Rule id: 7179
    Created at: 2020-11-09 10:41:04
    Updated at: 2020-11-09 10:42:15
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Cajino
{
    meta:
        Author = "R.R.J. Schreuder"
        Email = "rickie.schreuder@gmail.com"
        Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
        Date = "05/11/2020"
        Description = "This is a basic YARA rule for a CEO fraud with Caijno"
        Sample = "B3814CA9E42681B32DAFE4A52E5BDA7A"
    strings:
        $a = "method3/MainActivity.java"
        $b = "method3/BaiduUtils.java"
        $c = "getIt.java"
        $d = "getLocation.java"
        $e = "method2/BaiduUtils.java"

    condition:
        $a and $b and $c or all of them
}
