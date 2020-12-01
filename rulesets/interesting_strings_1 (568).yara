/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: interesting_strings_1
    Rule id: 568
    Created at: 2015-06-08 10:00:00
    Updated at: 2017-04-24 17:42:31
    
    Rating: #0
    Total detections: 2174402
*/

rule interesting_strings_1
{
meta:
 description = "Search for password string"
 author = "David Garcia"
 date = "2016-02-10"
 version = "1"
strings:
 $string_1 = { 64 72 6f 77 73 61 70 }
 $string_2 = "password"
condition:
 $string_1 or $string_2
}
