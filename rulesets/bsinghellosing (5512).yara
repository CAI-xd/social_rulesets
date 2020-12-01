/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: bsing.hellosing
    Rule id: 5512
    Created at: 2019-05-07 09:24:03
    Updated at: 2019-05-07 10:20:43
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"


rule koodous : official
{
	condition:
		androguard.permission(/com.bsing.hellosing.permission.C2D_MESSAGE/) or
		androguard.permission(/vn.cpgame.pokemonvictoryfire.permission.C2D_MESSAGE/)
}
