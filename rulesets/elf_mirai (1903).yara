/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: h3x2b
    Rule name: elf_Mirai
    Rule id: 1903
    Created at: 2016-10-12 16:27:54
    Updated at: 2016-10-12 16:33:01
    
    Rating: #0
    Total detections: 0
*/

rule mirai_20161004 : malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects Mirai samples - 20161004"
                //Check also:
                //http://tracker.h3x.eu/corpus/680
                //http://tracker.h3x.eu/info/680
                //http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html

        strings:
                $mirai_00 = "/dev/null"
        		$mirai_01 = "LCOGQGPTGP"


        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the strings
                all of ($mirai_*)
}
