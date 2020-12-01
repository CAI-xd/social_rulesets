/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: Monokle
    Rule id: 5785
    Created at: 2019-07-25 21:33:00
    Updated at: 2019-07-25 21:40:00
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Monokle : lookout
{
	meta:
		description = "Monokle Android. Malware. Trojan. RC. "
	


	condition:
		file.sha1("722fa5222be0686150bf7ef62097035b35babcb3") or
		file.sha1("655e2a59c80c05baabd88b417a078a1f085d2ed9") or
		file.sha1("5b9d7d9b8110b245f5d53b4aab4f23a5812c4815") or
		file.sha1("72d4863a4df5337621440222a478fbf8fa6d2c9a") or
		file.sha1("fe0d426ee22c0a18d0cdcd81d9742a426f30ebcf") or
		file.sha1("8034857623f59a3804c7170095e9e792a75c442d") or
		file.sha1("b4993b08bbb0482723502c2a52da5d0a30a00f45") or
		file.sha1("8fd1211deda8214dc7b1bb81522756aa88e6d116") or
		file.sha1("d93f45ae0967c514ec0bf5ccc4987a0bd2b219b4") or
		file.sha1("d9bfe9a0bef9c0a0dc021b33cc2d2a7899aa08a0") or
		file.sha1("5bcaecf74d242c8b1accbdf20ac91cacb6b5570a") or
		file.sha1("60d5d2336321f12041192956b3e9d27ea37e61e7") or
		file.sha1("a3af46875934a038e28cbf36153b6dd1a69d1d4b") or
		file.sha1("21e8a2aed43b66fbbeb1cf4839996e2d2dc27ed2") or
		file.sha1("f910d5a09b2f678df3f56106cef3e9c0c11ce62c") or
		file.sha1("9d7c44ef99054a208ce6e05cfd9ce4e16cf6f5fb") or
		file.sha1("e8fbf33849250900ea69e4b3cc0be96607d064ac") or
		file.sha1("501c295ec2d497ad87daa1d069885b945d372499") or
		file.sha1("5354a371c7a936daa26b2410bbf7812a31ae7842") or
		file.sha1("d13eda5c914dc5fec7984ff9a2e0987c357141d3") or
		file.sha1("9cbad8d15a6c96f8e587d4bf8d57882e57bf26d6") or
		file.sha1("b138dee2b40c8f1531098d6fb00b3d841fec5ed8") or
		file.sha1("bbbd7f1776bef967b93d7c381617310a62f5f6ff") or
		file.sha1("7a5421a20f834402e0ca318b921b7741b0493b34") or
		file.sha1("f9ab3ac4b67f512cde8dce50d2797eeddbc102f8") or
		file.sha1("f7e948a6100e11064094bf46eb21fb64b53db5d0") or
		file.sha1("f3541ce42f4197fd5363756b21c5ff74c7db295c") or
		file.sha1("0026ccb2c45f0dc67e41b736d8c0e1f0d8385146") or
		file.sha1("b1896570b50aca85af521fa1fb7ae86b8aeb26fe") or
		file.sha1("5feada28d38ee41b0b9f1a38458e838445201ef0") or
		file.sha1("025c427d354cbc0a2f473972d1b6a3a53f37017c") or
		file.sha1("3a350b419e9079c2cc6ec12f2430e4cee5446fa8") or
		file.sha1("d7db5c227ad23a43f2d3fe5e3cb7e3b31c82c86a") or
		file.sha1("6e186e713f38f3843735f576f5083f4f684cc077") or
		file.sha1("c70815dbdec80302d65d8cb46197a1d787479224") or
		file.sha1("04c8dcc62704526606d05037e1209b571e504792") or
		file.sha1("8ded74c9c7c61273adf9888506870911944ca541") or
		file.sha1("4245d4d349152e9706419f03756cc52f1570d255") or
		file.sha1("d9114cea50febed7d51e15077a1893494e52f339") or
		file.sha1("f4f47c9fec3e85657cfbde92c965913c70c93867") or
		file.sha1("b0911d5eeab68723c1d9fcdada2a64b5eace5f54") or
		file.sha1("8af9997e20949e0cc8dfcb685b5c1746921ee5d1") or
		file.sha1("1e0ac49b78cf2fa5cab093d5a56f15765bbddf31") or
		file.sha1("09b4972a6ee426b974e78ca868c1937bd3c83236") or
		file.sha1("e288de6ec6759275b1af2c2a353577cc88b8dd93") or
		file.sha1("f837a54e761edafd10e7d4872f81e5c57c0585be") or
		file.sha1("44b999f4c9284b5c34cec3ffb439cb65f0da5412") or
		file.sha1("69a86eb70ebf888fdd13c910e287b3d60393012b") or
		file.sha1("01390cd14b0f17efb90d89bdd9ff7de46e008a8f") or
		file.sha1("8e34ad5b12783b8c2c5d57ae81d8e3c4fe8bf1f4") or
		file.sha1("4f2873780794d654961644fb9c2e2750213a69f8") or
		file.sha1("346fe37f451cd61cfc922eafc113798b59c807be") or
		file.sha1("ef32335fd5457274ff65437aa1615c62c77772b4") or
		file.sha1("1bd8465f5020f75f0a84dfaf6e1e935954533368") or
		file.sha1("d618a5be838713d0a117c7db2775e7614a775924") or
		file.sha1("720b29792f80c02c42c48b7d085035cd1a28ec68") 
		
}
