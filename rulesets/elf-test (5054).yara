/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: ELF test
    Rule id: 5054
    Created at: 2018-11-09 18:07:11
    Updated at: 2018-11-09 18:08:01
    
    Rating: #0
    Total detections: 0
*/

import "elf"

rule single_section
{
    condition:
        elf.number_of_sections >= 1
}
