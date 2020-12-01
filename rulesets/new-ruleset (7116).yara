/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wassol
    Rule name: New Ruleset
    Rule id: 7116
    Created at: 2020-11-02 15:11:42
    Updated at: 2020-11-03 14:16:48
    
    Rating: #0
    Total detections: 0
*/

rule PornHubAPK
{
    meta:
        Author = "Wessel van Putten and Niels Cluistra"
        email = "s2600889@vuw.leidenuniv.nl"
        description = "A rule to detect the malicious APK in the PornHub app"
    
    strings:
        $a= "Vgamqwt" 
        $b= "Wunec"
        $c= "android.permission.QUICKBOOT_POWERON"
        $d= "android.permission.WRITE_EXTERNAL_STORAGE"
    
    condition:
        $a and $b and $c and $d
}
