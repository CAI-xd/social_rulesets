/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: cocaman
    Rule name: android_coinhive_fake_hack_app
    Rule id: 3967
    Created at: 2018-01-07 21:37:01
    Updated at: 2018-01-29 19:26:38
    
    Rating: #0
    Total detections: 1018
*/

rule android_coinhive_fake_hack_app {
  meta:
		description = "This rule detects Android Fake App, that uses Coinhive"
		author = "Corsin Camichel, @cocaman"
		version = "2018-01-07"
		in_the_wild = true
    tlp = "green"

  strings:
    $string_1 = "Jakaminen:"
    $string_2 = "Hack"
    $string_3 = "initialActivityCount"

  condition:
  	all of ($string_*)

}
