/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wendalereg
    Rule name: PornPlayer_URL
    Rule id: 1659
    Created at: 2016-07-21 09:45:17
    Updated at: 2016-07-21 10:01:43
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule PornPlayer_URL
{
	meta:
		description = "This rule detects PornPlayer by network traffic keywords, like /ckplayer/style.swf"
		sample = ""
		examples = "33vid.com/,	44ytyt.com/, 8765kkk.com/, avsss66.com/, avsss88.com/, ffcao11.com/media/ckplayer/"
				  

	condition:
		androguard.url(/\/ckplayer\/style\.swf/) or
		cuckoo.network.http_request(/\/ckplayer\/style\.swf/)
}
