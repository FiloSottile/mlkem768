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
	// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-05.html#appendix-C
	seed, _ := hex.DecodeString("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	pkExp, _ := hex.DecodeString("e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534")
	ct, _ := hex.DecodeString("b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c1244b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb8870dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e55456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ffc346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102ba3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe463899b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16eac1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee09367976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b776002d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc81bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99fdbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f518fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe62d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b35fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b24314cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd3099b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e03806ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd37591578f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d632407f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15")
	ssExp, _ := hex.DecodeString("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")

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
