/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: phoogerheide
    Rule name: bankingapps
    Rule id: 2674
    Created at: 2017-05-10 13:19:03
    Updated at: 2017-10-27 09:49:20
    
    Rating: #0
    Total detections: 5824
*/

import "androguard"


rule bankingapps
{
	strings:
	  $ = "com.ingbanktr.ingmobil"
	  $ = "com.ing.mobile"
	  $ = "au.com.ingdirect.android"
	  $ = "de.ing_diba.kontostand"
	  $ = "com.ing.diba.mbbr2"
	  $ = "com.IngDirectAndroid"
	  $ = "pl.ing.ingmobile"
	condition:
		1 of them
}
