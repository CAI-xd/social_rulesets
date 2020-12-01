/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dmaciejak
    Rule name: DroidJack
    Rule id: 2773
    Created at: 2017-05-25 02:38:23
    Updated at: 2017-06-12 06:56:07
    
    Rating: #0
    Total detections: 210
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : DroidJack
{
	meta:
		author = "dma"
		sample = "81c8ddf164417a04ce4b860d1b9d1410a408479ea1ebed481b38ca996123fb33"

	condition:
		androguard.activity(/net\.droidjack\.server\./i)
}
