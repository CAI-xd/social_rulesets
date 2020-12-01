/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sarcares
    Rule name: Send Payment SMS - Scanning using URLs
    Rule id: 3047
    Created at: 2017-06-26 22:25:10
    Updated at: 2018-04-11 18:14:53
    
    Rating: #0
    Total detections: 1970
*/

import "androguard"
import "file"

rule SmsFraudUsingUrls : smsfraud
{
	meta:
		cluster_url = "https://koodous.com/apks?search=57392579046725034bb95dd1f60dc6de61b4ea8dc8a74c6567f389874248dd85%20OR%20365264012541ee0991afc7344e0f8c34e6a0166b76b7b3e82f2a2458262aca79%20OR%20c3d41e5b91c1c436fcaf3f3ccf053b17a6c9ff609d5b75dbbf162a3aaf211992%20OR%2087aa082a58590a3ed721c43ada4974d2257012748b25377815a8c57be5212be6%20OR%208fa10258025b49963793d9864ba344d426f2f952a7b082a9a0e6a4888ce55ba7%20OR%2034c4d8a7947c83c773af1bc682d1a389ef8dc25e3d8ac02b2ecb469949be3a74%20OR%2013eebcb6b37d40267fdcfc1b778c3cd57a663ccea736fd6256aaa69666b6819f%20OR%20db96bf5052a29fb6b44c270bfb94294ce90f05dbc5aba7fcab3729a0ca89245c%20OR%20396ec6d18430abe8949ddc39cf10d008e189be9b41fff598cfde73a67987da5e%20OR%209a69a20ae5128e5646ac84334a1a86cdb6cba95d93c6bba5e6e143fa5f6ad226%20OR%200b14afb604707f1348d3e6a3d949255033e233f1300a4346b37dda69edbddc3c%20OR%209f8a76bf08c49d2ea9984303210ad65e57d39504a3f6a032e6126039039d4689%20OR%203c9d52e75a37645a726bd5373f176767eab3c67a6e97f12650f81a6faa7d7598%20OR%20a7fb9d9317d2593da7b45af032e16729612378d9bdc124812348bc3fb720fd9a%20OR%203d314d5ba462fa1bfb1f940c9760fe925318e1ec3990190f238be44cf1bded8a%20OR%20f64609a98cc6e3f23b210bc1d87a2d1cd969b4a7561f2d18073c7804ca8e4b93%20OR%203a9e7545301c7dee2d3e90ab350710b30acf4aea30e221b88829761c91f24ca1%20OR%20cb7a6e6c60ae51e3eb38e3956b46de607769aa37e172a62c40579487cb36ebd2%20OR%20aa72e50e45767bf57f0edd6874fc79430dec6bd9314b50c3ba020748ed5c17c2%20OR%203eabcb500ca484091897365263e48add7904ad1e67956a09cffb94f60ba0389d"
		description = "This rule should match applications that send SMS"

	condition:
		androguard.url(/tools\.zhxapp\.com/)
		or androguard.url(/app\.tbjyz\.com\/tools\/zhxapp_hdus(\w+)?/)
}
