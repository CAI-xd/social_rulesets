/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Slocker/Pornlocker
    Rule id: 7001
    Created at: 2020-07-15 13:47:41
    Updated at: 2020-07-15 13:47:46
    
    Rating: #0
    Total detections: 0
*/

rule PornSlocker
{
	meta:
		description = "This rule detects some common used pictures or other files in SLocker / PornLocker variants"

strings:

	  $ = "+peNAqsEDqAiIB5C1bI1ABJUQhw"
      $ = "20j5H7HXFJMGsBIGYI426RQpQnQ"
      $ = "4Sx38f55G9Jr+XOyr3jbjky7fD4"
      $ = "5zokrOTkM2EsbSZIeCjbKBc4ci4"
      $ = "OxFElpi2+oBqlQHh3jk+3fMD9Y8"
      $ = "Wc1rLTQNhJtMbIiyNxmyw1jcNS8"
      $ = "YPcRkdktCfVzEA4Fd83WkmXnO3w"
      $ = "ZqjexisfZj0WmcuFhrJhh6jB2Gk"
      $ = "pH7PIBTiJ94EaJWpZa1ITsUP1FI"	 
     
	
	condition:
		1 of them
}
