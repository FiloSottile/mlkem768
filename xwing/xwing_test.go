package xwing

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, Ke, err := Encapsulate(dk.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	Kd, err := Decapsulate(dk, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Errorf("Ke != Kd")
	}

	dk1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey(), dk1.EncapsulationKey()) {
		t.Errorf("ek == ek1")
	}
	if bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Errorf("dk == dk1")
	}

	dk2, err := NewKeyFromSeed(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Errorf("dk != dk2")
	}

	c1, Ke1, err := Encapsulate(dk.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, c1) {
		t.Errorf("c == c1")
	}
	if bytes.Equal(Ke, Ke1) {
		t.Errorf("Ke == Ke1")
	}
}

var sink byte

func BenchmarkKeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk, err := GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		sink ^= dk.EncapsulationKey()[0]
	}
}

func BenchmarkEncaps(b *testing.B) {
	dk, err := GenerateKey()
	ek := dk.EncapsulationKey()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, K, err := Encapsulate(ek)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= c[0] ^ K[0]
	}
}

func BenchmarkDecaps(b *testing.B) {
	dk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	c, _, err := Encapsulate(dk.EncapsulationKey())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		K, err := Decapsulate(dk, c)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= K[0]
	}
}

func TestVector(t *testing.T) {
	// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-04.html#appendix-C
	seed, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	pkExp, _ := hex.DecodeString("ec367a5c586f3817a98698b5fc4082907a8873909a7e79ce5d18c84d425362c7956aeb610b9b68949107335ba676142aadd93ed27211c57c2d319c805a01204f5c2948158759f06327825379ac8428113e59c215a582a50d0c89505390ecf868e9270cf96c4fa0f94793b5998b38a1e3c9039bf4147695c08413a7e190b5d9a8c22a4759bda51fd11064a21c4dadc3bc28510697f3a442205214a6cd3f54a9ba45a309437d372654e2c6226e8640810128597abe9042932be6af1eb71a6ef156a9baa4c0c05764a8314fc1565d1825a5eb3604f278bc175b0666af85a13d97c650a571564eca080a36727bf76460c81a842895e87c9d4fc9c57fc6b149692eed526fb632cd476232a9f3035b4c96d6a14f8cf92e2735a766c7a168e6034369b6c17750afcc483af5654b82439f6b9a136cb4f47986dab4c427327675061d7b130572e2071f22339a997cf1e1618133ac8b8acd1d7177943c0d1971c84fc48cce7c4c00b95a9f77414c4c07fb3b0c6d51144d36cc8be4ae9b236f89accdd4336bcff11f4fc997ef13c01bb45d4001b1949749ebf14e469788ebdbbeced68ba149ca81aab111d0756f1074b7e60031da437709027c4676edc35318a74b1308a8f2b6aef905668bb031a6403ab7a328ba74b9231866e287424b42acd1d69b6eab657f2340f433717e581a048ac9be5196fedc36ec212de48149bbec9e07ccc8b1f50293e78e469079a3d3588ae146c1859ced376dc13040c4535f253cb40a61b8be95b8b6606d2f607c1035a23566ade289391829ae61cacd36d247a3a864bab43b23198481f10f9a5b25b64cb6314baaa0282c59792fe987687b06cb23b397302962cacb9f7327301310c7e66b9f5aab93b0f9ba9b5633a1db72fa637c4f6611ca9117788bb335b80dd0c989af6b0d8fc9b5c3707a1d848b220a3002b612c294a004c4b52ad1b4b57619d960a659646622a73de9a55de1191dcf8253b50bb2d6e0bed3ab12c4bb81b2826afec87dabccb56b74bdd4c844005097ac94cafea715a57b6e20b49e49869bfdc8015e37a0b3f942f9467b7c749f76c951623340660bbd88c16dfbf5176ca855689bbf7287391935b71eda6ef8bab6a2ea6e3095a1f2719d10b205130982942c1bbad0bb6c1901879587ac3a290ff20043010e181337eb2a20eda44b24e07f12255bbe78279adc51de276d2e602b72dc1ed7489240ab2c4e672b527082e363b0b5f51ffbbb79d724435484ca0c7874aff654d61a254eb7ae420b4d0a9958a48144e013972cda7f8adcc7c36206725221a79426e7c798e99cb645198c506194c3da36415501ea6bccb377921f0172cf9634232b211d626074020cdec29c4d59248c405688f15d6bc556f72bb01d11ae0b2167d33bb2389a2d6dec911a3513fc680d21a265c3f3b190e983d5bab1ae471802024edfd96a2cd51176261107c29f5050ab52ca7210db8668bb80064744cb4236e3ac6df26477c8d80ac9a60ca8796f95c5acd960b2f541027c2378ac15708070acfa528a8473248458cb3cf23108949369009b523a945fc70cf3c3add61c4fbbdba91d74c954682182d30071e71648f1b266ea343ab97547c9a3462969ca911a67667e1cb88467942eea1ae5d06ac215e64de876fda67c22f74ffe26ff8b56cf606ff799d4a89bb6cee3f79506960abcda4e65d8197e0c992244dae91c21068915647f844f49")
	ct, _ := hex.DecodeString("b45085dc0c2abecd811415924ade853ae88c8dcf8007e6d79bae036648290472989d6f2187bc6d39d0f739d315fc03cd8a373ad8927b0db7d419385c9b867b351815a95e7f0f915e7356eacce50d328a572565c538b282dc539e4d4b106ba5add0656efb8bd670a32e89fb642eae8235fdc181b2a3ae21d5f3374ce6955484c4fa9dd0a8e454f73e840fa5085070d10789e3cc1f6b4274fad17c041c23a8c512e3be23962de5028f427273f5a53dcf43425e9183d304abf22b306fb6add4c89a7b54fa93d50393882bad23e06c58c03cbb765a9d1324be9fe7b399b7a0f7486b8b03fe186dc5e9ee9738f48e7ef3127a6db992097263dbc51fb227dfab0aae2758d8cfd8573c227e19d245503518ee7f533976236075d50f95b5bd101c670714209f264c01e31b80295fea54f42e1c62856042bafbe72e1ef8abe12f58b02e4eb6378bc0e13339395b6faf95e2738c509975bc1806d1cbad3e586cfa2ba09b2bde20dfb0aaba2cdb583ae33c812109a1095adc697befcbd0be0aafee1e41979be026747c918646d38874320aaf404f28cda6d6d7a7a5386f487983a69064b8bc1fc0a2998a55bb442cfa9b61581263b33f5ae25c4a1efdd890c3fae4481995eaabf1d4a27addc239b99bb8aefec73a9f9c15819026d35d48e11de426f7f113e8fe843db011934c8052300cca9fc870f390648ab47ff543629949c5459fae763871e949a4d2f61caf9f6afcfbc00e5b71f85c791ae04d4db90ed09811382a8a2a9707f76cbeaa371eb64d2a8d82e1f65b42e0928e5afa288062ca0b28317c9b36b27f14161d84d71db377efc6f0f2d7b57594e8fc432c2dbcbc4f55fc3563894a5be4ad40a2aa34ca48db0df5b6d8ae51777bf7c6925a40e651629351e86480594f438ee3a34daa7a2581e0f573489e71b23bf76dcf8fd3d9c29ca6bcc699753d54b876adb0c0514ae887e1029ef195fc3cddb51d03cb518f8dad5044e2299f601b961fa38da47d1e940b58e864cf5dbe85a21dafc40b2355144307d09bd2bf8b1c762e7bd5e27308d903e165ecc6176b74564329bf37e1ce9257d113897c0099aaa17937735dd13931c5742f5cceaec475c1886bfef42252a7ad66f4d4b925faec8e1a9ce0623a895e9c00c57781e66404311720bb94ff0c019081f9b846d72451179308f17d4c7ac324a5bbbb914411840364b9b65f6e189c60ef842c155df1f96b84f03521803d3cb7016629b4c8159fb0ad3ce1da5e49ceba56f6881be8432200c86e291a4cd3b5ea9001e99b418b9d44a3fa0cedb6acf3feef30df4307480967e765530d6183add3a198d796a4535abbd8be92d8c2f9ec4217fd459326f0f090764b57207d4cb108af34abf120c182011e66393edf2f446f606acb5b0ad5afb4ea5866e4d4158280885bd0ad4deced058ced8035afc85d1e03c00b7c23b4e74abe8ba12b86a027064bf88443aadb38c82bc621b6880d3e88f6c3bcb03a015d1cc306f7d575ee778cd1b52902be555b4e02b74cfd310bd83ab4c81f97fc12e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15")
	ssExp, _ := hex.DecodeString("555a071a8b7520ae95f8e635de8a5f87dbddcbef900576aad29ecdda5459c15a")

	sk, err := NewKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk.EncapsulationKey(), pkExp) {
		t.Errorf("pk != pkExp")
	}

	if _, _, err := Encapsulate(sk.EncapsulationKey()); err != nil {
		t.Fatal(err)
	}

	ss, err := Decapsulate(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, ssExp) {
		t.Errorf("ss != ssExp")
	}
}
