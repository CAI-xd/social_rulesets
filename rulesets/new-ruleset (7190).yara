/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wassol
    Rule name: New Ruleset
    Rule id: 7190
    Created at: 2020-11-09 13:13:15
    Updated at: 2020-11-09 13:14:41
    
    Rating: #0
    Total detections: 0
*/

rule BadNewsAPK
{
    meta:
        Author = "Wessel van Putten and Niels Cluistra"
        email = "s2600889@vuw.leidenuniv.nl"
        description = "A rule to detect the malicious BadNews APK"
    
    strings:
        $a= "fillPostDate.java" 
        $b= "onStartCommand.java"
        $c= "startUpdater.java"
        $d= "sendRequest.java"
    
    condition:
        $a and $b and $c and $d
}
