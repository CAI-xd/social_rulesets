/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ninoseki
    Rule name: FakeSpy
    Rule id: 6128
    Created at: 2019-11-25 11:35:52
    Updated at: 2019-11-25 11:40:42
    
    Rating: #0
    Total detections: 0
*/

rule FakeSpy {
   strings:
      $a = "AndroidManifest.xml"
      $b = "lib/armeabi/librig.so"
      $c = "lib/armeabi-v7a/librig.so"
   condition:
      $a and ($b or $c) and (filesize > 2MB and filesize < 3MB)
}
