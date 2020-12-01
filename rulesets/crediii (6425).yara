/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dieee
    Rule name: Crediii
    Rule id: 6425
    Created at: 2020-02-27 12:40:47
    Updated at: 2020-02-27 12:44:31
    
    Rating: #0
    Total detections: 19
*/

rule credicorp {

	strings:
		$string_1 = /splashscreentest/
		$string_2 = /pacifico.miespacio/
		$string_3 = /pacifico.iwant/
		$string_4 = /bcp.benefits/
		$string_5 = /innovacxion.yapeapp/
		$string_6 = /bcp.bank/
		$string_7 = /bnfc.npdb/
		$string_8 = /coebd.paratiapp/
		$string_9 = /coebd.manyar/
		$string_10 = /innovaxcion.pagafacil/
		$string_11 = /bank.tlc/
		$string_12 = /bo.discounts/
		$string_13 = /bcp.bo.wallet/
		$string_14 = /mobile.credinetweb/
		$string_15 = /mibanco.bancamovil/
		$string_16 = /benefits.mibanco/
		$string_17 = /bederr.mibancoapp/
		$string_18 = /dataifx.credicorp/
		$string_19 = /credicorp19/
		$string_20 = /indisac.link2019/
		
		
	condition:
		any of them
}
