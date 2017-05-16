/*
 * testAnyFunc.c
 *
 *  Created on: Apr 23, 2017
 *      Author: cossete
 */

#include "common.h"
#include "hash.h"
#include "varint.h"
#include "ec.h"
#include "base58.h"
#include "tx.h"

int main() {

//	use integers to test serialization
//	uint8_t n8 = 0x01;
//	uint16_t n16 = 0x4523;
//	uint32_t n32 = 0xcdab8967;
//	uint64_t n64 = 0xdebc9a78563412ef;
//	uint8_t ser[15];
//
//	const char ser_exp[] = "0123456789abcdef123456789abcde";
//
//	*ser = n8;
//	*(uint16_t *)(ser + 1) = eint16(LITTLE, n16);
//	*(uint32_t *)(ser + 3) = eint32(LITTLE, n32);
//	*(uint64_t *)(ser + 7) = eint64(LITTLE, n64);
//
//	print_hex("ser      ", ser, sizeof(ser));
//	printf("ser (exp): %s\n", ser_exp);
//
//
//
//


//
//
//
//	use strings to test serialization
//	uint32_t n32 = 0x68f7a38b;
//	char str[] = "FooBar";
//	size_t str_len = 10;
//	uint16_t n16 = 0xee12;
//	uint8_t ser[16];
//
//	const char ser_exp[] = "8ba3f768466f6f4261720000000012ee";
//
//	size_t str_real_len = strlen(str);
//	size_t str_pad_len = str_len - str_real_len;
//
//	*(uint32_t *)(ser) = eint32(LITTLE, n32);
//	memcpy(ser + 4, str, str_real_len);
//	if (str_pad_len > 0) {
//	memset(ser + 4 + str_real_len, '\0', str_pad_len);
//	}
//	*(uint16_t *)(ser + 4 + str_len) = eint16(LITTLE, n16);
//
//	print_hex("ser      ", ser, sizeof(ser));
//	printf("ser (exp): %s\n", ser_exp);
//
//
//


//
//
//
//	use hash256 to test serialization
//	char message[] = "Hello Bitcoin!";
//	uint16_t prefix = 0xd17f;
//	uint8_t suffix = 0x8c;
//	uint8_t digest[32];
//	uint8_t ser[35];
//
//	const char sha256_exp[] = "518ad5a375fa52f84b2b3df7933ad685eb62cf69869a96731561f94d10826b5c";
//	const char hash256_exp[] = "90986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda";
//	const char ser_exp[] = "7fd190986ea4e28b847cc7f9beba87ea81b221ca6eaf9828a8b04c290c21d891bcda8c";
//
//	sha256(digest, (uint8_t *)message, strlen(message));
//	print_hex("SHA256(message)      ", digest, 32);
//	printf("SHA256(message) (exp): %s\n", sha256_exp);
//
//	sha256(digest, digest, 32);
//	print_hex("hash256(message)      ", digest, 32);
//	printf("hash256(message) (exp): %s\n", hash256_exp);
//
//	*(uint16_t *)(ser) = eint16(LITTLE, prefix);
//	memcpy(ser + 2, digest, 32);
//	*(ser + 2 + 32) = suffix;
//
//	print_hex("ser      ", ser, sizeof(ser));
//	printf("ser (exp): %s\n", ser_exp);
//
//


//
//
//
//	variable data with self-defined prefix which is used to check data size
//	uint8_t bytes[] = {
//	0xfd, 0x0a, 0x00, 0xe3,
//	0x03, 0x41, 0x8b, 0xa6,
//	0x20, 0xe1, 0xb7, 0x83,
//	0x60
//	};
//
//	size_t len;
//	size_t varlen;
//	uint8_t data[100] = { 0 };
//
//	const char data_exp[] = "e303418ba620e1b78360";
//
//	/* */
//
//	len = varint_get(bytes, &varlen); /*varint_get will use the prefix to decide data size (in bytes)*/
//	printf("len: %lu, varlen: %lu\n", len, varlen);
//
//	memcpy(data, bytes + varlen, len);
//
//	print_hex("data      ", data, len);
//	printf("data (exp): %s\n", data_exp);








//  use the function of ec.h to create key pair, mostly learn OpenSSL website
//	uint8_t priv_bytes[32] = {
//		0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
//		0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
//		0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
//		0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
//	};
//
//	EC_KEY *key;
//	uint8_t priv[32];
//	uint8_t *pub;
//	const BIGNUM *priv_bn;
//
//	point_conversion_form_t conv_forms[] = {
//		POINT_CONVERSION_UNCOMPRESSED,
//		POINT_CONVERSION_COMPRESSED
//	};
//	const char *conv_forms_desc[] = {
//		"uncompressed",
//		"compressed"
//	};
//	int i;
//
//	const char priv_exp[] = "16260783e40b16731673622ac8a5b045fc3ea4af70f727f3f9e92bdd3a1ddc42";
//	const char pub_exp[2][200] = {
//		"0482006e9398a6986eda61fe91674c3a108c399475bf1e738f19dfc2db11db1d28130c6b3b28aef9a9c7e7143dac6cf12c09b8444db61679abb1d86f85c038a58c",
//		"0282006e9398a6986eda61fe91674c3a108c399475bf1e738f19dfc2db11db1d28"
//	};
//
//	/* create keypair */
//
//	key = ec_new_keypair(priv_bytes);
//	if (!key) {
//		puts("Unable to create keypair");
//		return -1;
//	}
//	print_hex("priv #1   ", priv_bytes, sizeof(priv));
//
//	/* get private key back from EC_KEY */
//
//	priv_bn = EC_KEY_get0_private_key(key);
//	if (!priv_bn) {
//		puts("Unable to decode private key");
//		return -1;
//	}
//	BN_bn2bin(priv_bn, priv);
//	print_hex("priv #2   ", priv, sizeof(priv));
//
//	printf("priv (exp): %s\n", priv_exp);
//
//	/* get encoded public key from EC_KEY in all conversion forms */
//
//	for (i = 0; i < sizeof(conv_forms) / sizeof(point_conversion_form_t); ++i) {
//		size_t pub_len;
//		uint8_t *pub_copy;
//
//		EC_KEY_set_conv_form(key, conv_forms[i]);
//
//		pub_len = i2o_ECPublicKey(key, NULL);
//		pub = calloc(pub_len, sizeof(uint8_t));
//
//		/* pub_copy is needed because i2o_ECPublicKey alters the input pointer */
//		pub_copy = pub;
//		if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
//			puts("Unable to decode public key");
//			return -1;
//		}
//
//		printf("conversion form: %s\n", conv_forms_desc[i]);
//		print_hex("pub      ", pub, pub_len);
//		printf("pub (exp): %s\n", pub_exp[i]);
//
//		free(pub);
//	}
//
//	/* release keypair */
//
//	EC_KEY_free(key);








//	use ECDSA to sign a arbitrary messages
//	uint8_t priv_bytes[32] = {
//		0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
//		0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
//		0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
//		0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
//	};
//	const char message[] = "This is a very confidential message\n";
//
//	EC_KEY *key;
//	uint8_t digest[32];
//	ECDSA_SIG *signature; /*ECDSA signature is (r,s) pair, OpenSSL define*/
//	uint8_t *der, *der_copy;
//	size_t der_len;
//
//	const char digest_exp[] = "4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01";
//
//	/* */
//
//	key = ec_new_keypair(priv_bytes);
//	if (!key) {
//		puts("Unable to create keypair");
//		return -1;
//	}
//
//	sha256(digest, (uint8_t *)message, strlen(message));
//	print_hex("digest      ", digest, 32);
//	printf("digest (exp): %s\n", digest_exp);
//
//	signature = ECDSA_do_sign(digest, sizeof(digest), key);
//	printf("r: %s\n", BN_bn2hex(signature->r));
//	printf("s: %s\n", BN_bn2hex(signature->s));
//
//	der_len = ECDSA_size(key);
//	der = calloc(der_len, sizeof(uint8_t));
//	der_copy = der;
//	i2d_ECDSA_SIG(signature, &der_copy);
//	print_hex("DER-encoded", der, der_len);
//
//	free(der);
//	ECDSA_SIG_free(signature);
//	EC_KEY_free(key);








//	use public key to verify the signature
//	uint8_t pub_bytes[33] = {
//		0x02,
//		0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
//		0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
//		0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
//		0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
//	};
//	/*der_bytes is a signature from previous test*/
//	uint8_t der_bytes[] = {
//		0x30, 0x44, 0x02, 0x20, 0x2b, 0x2b, 0x52, 0x9b,
//		0xdb, 0xdc, 0x93, 0xe7, 0x8a, 0xf7, 0xe0, 0x02,
//		0x28, 0xb1, 0x79, 0x91, 0x8b, 0x03, 0x2d, 0x76,
//		0x90, 0x2f, 0x74, 0xef, 0x45, 0x44, 0x26, 0xf7,
//		0xd0, 0x6c, 0xd0, 0xf9, 0x02, 0x20, 0x62, 0xdd,
//		0xc7, 0x64, 0x51, 0xcd, 0x04, 0xcb, 0x56, 0x7c,
//		0xa5, 0xc5, 0xe0, 0x47, 0xe8, 0xac, 0x41, 0xd3,
//		0xd4, 0xcf, 0x7c, 0xb9, 0x24, 0x34, 0xd5, 0x5c,
//		0xb4, 0x86, 0xcc, 0xcf, 0x6a, 0xf2
//	};
//	const char message[] = "This is a very confidential message\n";
//
//	EC_KEY *key;
//	const uint8_t *der_bytes_copy;
//	ECDSA_SIG *signature;
//	uint8_t digest[32];
//	int verified;
//
//	const char *r_exp = "2B2B529BDBDC93E78AF7E00228B179918B032D76902F74EF454426F7D06CD0F9";
//	const char *s_exp = "62DDC76451CD04CB567CA5C5E047E8AC41D3D4CF7CB92434D55CB486CCCF6AF2";
//	const char *digest_exp = "4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01";
//
//	/* */
//
//	key = ec_new_pubkey(pub_bytes, sizeof(pub_bytes));/*decode pub_bytes to public key, fnuction in ec.h*/
//	if (!key) {
//		puts("Unable to create keypair");
//		return -1;
//	}
//
//	der_bytes_copy = der_bytes;
//	signature = d2i_ECDSA_SIG(NULL, &der_bytes_copy, sizeof(der_bytes));/*change der format to ECDSA_SIG format*/
//	printf("r      : %s\n", BN_bn2hex(signature->r));
//	printf("r (exp): %s\n", r_exp);
//	printf("s      : %s\n", BN_bn2hex(signature->s));
//	printf("s (exp): %s\n", s_exp);
//
//	sha256(digest, (uint8_t *)message, strlen(message));/*create the hash of messages*/
//	print_hex("digest      ", digest, 32);
//	printf("digest (exp): %s\n", digest_exp);
//	verified = ECDSA_do_verify(digest, sizeof(digest), signature, key);/*only take ECDSA_SIG format*/
//
//	switch (verified) {
//		case 1:
//			puts("verified");
//			break;
//		case 0:
//			puts("not verified");
//			break;
//		case -1:
//			puts("library error");
//			break;
//	}
//
//	ECDSA_SIG_free(signature);
//	EC_KEY_free(key);







//	convert private key to WIF format
//	uint8_t priv_bytes[32] = {
//		0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
//		0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
//		0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
//		0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
//	};
//	uint8_t wif_bytes[34];
//	char *wif;
//
//	const char wif_exp[] = "cNKkmrwHuShs2mvkVEKfXULxXhxRo3yy1cK6sq62uBp2Pc8Lsa76";
//
//	/* */
//
//	print_hex("priv", priv_bytes, sizeof(priv_bytes));
//
//	wif_bytes[0] = 0xef;        /*Testnet3 prefix*/
//	memcpy(wif_bytes + 1, priv_bytes, 32);
//	wif_bytes[33] = 0x01;       /*append 01 if wif correspond to a compressed public key*/
//
//	wif = base58check(wif_bytes, 34);
//	printf("WIF      : %s\n", wif);     /*up to 38 bytes*/
//	printf("WIF (exp): %s\n", wif_exp);
//	free(wif);






//	create P2PKH address with public key, BTW Testnet3
//	uint8_t pub_bytes[33] = {
//		0x02,
//		0x82, 0x00, 0x6e, 0x93, 0x98, 0xa6, 0x98, 0x6e,
//		0xda, 0x61, 0xfe, 0x91, 0x67, 0x4c, 0x3a, 0x10,
//		0x8c, 0x39, 0x94, 0x75, 0xbf, 0x1e, 0x73, 0x8f,
//		0x19, 0xdf, 0xc2, 0xdb, 0x11, 0xdb, 0x1d, 0x28
//	};
//	uint8_t address_bytes[21];
//	char *address;
//
//	const char address_exp[] = "mqMi3XYqsPvBWtrJTk8euPWDVmFTZ5jHuK";
//
//	/* */
//
//	print_hex("pub", pub_bytes, sizeof(pub_bytes));
//
//	address_bytes[0] = 0x6f;                    /*Testnet3 prefix*/
//	hash160(address_bytes + 1, pub_bytes, 33);
//	print_hex("hash160", address_bytes + 1, 20);
//
//	address = base58check(address_bytes, 21);
//	printf("address      : %s\n", address);     /*up to 25 bytes*/
//	printf("address (exp): %s\n", address_exp);
//	free(address);








//	collect UTXO, create output one for transfer, one for change
//	create the modified tx to be signed for the input signature
//	txout_t outs[2];
//	txout_t prev_outs[1];
//	txin_t ins_sign[1];
//	outpoint_t outpoint;
//	tx_t tx;
//	uint8_t *msg;
//	size_t msg_len;
//
//	const char msg_exp[] = "0100000001f3a27f485f9833c8318c490403307fef1397121b5dd8fe70777236e7371c4ef3000000001976a9146bf19e55f94d986b4640c154d86469934191951188acffffffff02e0fe7e01000000001976a91418ba14b3682295cb05230e31fecb00089240660888ace084b003000000001976a9146bf19e55f94d986b4640c154d86469934191951188ac0000000001000000";
//
//	/* */
//
//	/* output 1 (0.251 BTC) */
//	txout_create_p2pkh(&outs[0], 25100000, "18ba14b3682295cb05230e31fecb000892406608");
//
//	/* output 2 (change, 0.619 BTC) */
//	txout_create_p2pkh(&outs[1], 61900000, "6bf19e55f94d986b4640c154d864699341919511");
//
//	/* input from utxo (0.87 BTC) */
//	outpoint_fill(&outpoint, "f34e1c37e736727770fed85d1b129713ef7f300304498c31c833985f487fa2f3", 0);
//	txout_create_p2pkh(&prev_outs[0], 87000000, "6bf19e55f94d986b4640c154d864699341919511");
//	txin_create_signable(&ins_sign[0], &outpoint, &prev_outs[0]);
//
//	/* message */
//	/*original tx after modified is the message gonna be signed*/
//	tx.version = eint32(LITTLE, 1);
//	tx.outputs_len = 2;
//	tx.outputs = outs;
//	tx.inputs_len = 1;
//	tx.inputs = ins_sign;
//	tx.locktime = 0;
//	msg_len = tx_size(&tx, SIGHASH_ALL);
//	msg = malloc(msg_len);
//	tx_serialize(&tx, msg, SIGHASH_ALL);
//
//	/* */
//
//	print_hex("outs[0].script", outs[0].script, outs[0].script_len);
//	print_hex("outs[1].script", outs[1].script, outs[1].script_len);
//	puts("");
//	print_hex("ins_sign[0].outpoint.txid", ins_sign[0].outpoint.txid, 32);
//	printf("ins_sign[0].outpoint.index: %u\n", ins_sign[0].outpoint.index);
//	print_hex("ins_sign[0].script", ins_sign[0].script, ins_sign[0].script_len);
//	puts("");
//	print_hex("msg      ", msg, msg_len);
//	printf("msg (exp): %s\n", msg_exp);
//
//	free(msg);
//	txout_destroy(&outs[0]);
//	txout_destroy(&outs[1]);
//	txout_destroy(&prev_outs[0]);
//	txin_destroy(&ins_sign[0]);








	txin_t ins[1];
	txout_t outs[2];
	outpoint_t outpoint;
	tx_t tx;
	uint8_t *rawtx;
	size_t rawtx_len;
	uint8_t txid[32];

	const char txid_exp[] = "9996e2f64b6af0232dd9c897395ce51fdd35e6359edd2855c60ff823d8d657d1";

	/* */

	/* inputs */
	/*create signature by signing the hash256 of the message built just now, der-encoded*/
	outpoint_fill(&outpoint, "f34e1c37e736727770fed85d1b129713ef7f300304498c31c833985f487fa2f3", 0);
	txin_create_p2pkh(&ins[0], &outpoint, "30440220111a482aba6afba12a6f27de767dd4d06417def665bd100bc68c42845c752a8f02205e86f5e054b2c6cac5d663664e35779fb034387c07848bc7724442cacf659324", "0282006e9398a6986eda61fe91674c3a108c399475bf1e738f19dfc2db11db1d28", SIGHASH_ALL);

	/* outputs */
	txout_create_p2pkh(&outs[0], 25100000, "18ba14b3682295cb05230e31fecb000892406608");
	txout_create_p2pkh(&outs[1], 61900000, "6bf19e55f94d986b4640c154d864699341919511");

	/* packing */
	tx.version = eint32(LITTLE, 1);
	tx.outputs_len = 2;
	tx.outputs = outs;
	tx.inputs_len = 1;
	tx.inputs = ins;
	tx.locktime = 0;
	rawtx_len = tx_size(&tx, 0);
	rawtx = malloc(rawtx_len);
	tx_serialize(&tx, rawtx, 0);

	/* txid (print big-endian) */
	hash256(txid, rawtx, rawtx_len);
	reverse(txid, 32);

	/* */

	print_hex("ins[0].script", ins[0].script, ins[0].script_len);
	print_hex("outs[0].script", outs[0].script, outs[0].script_len);
	print_hex("outs[1].script", outs[1].script, outs[1].script_len);
	puts("");
	print_hex("rawtx", rawtx, rawtx_len);
	printf("size: %lu bytes\n", rawtx_len);
	puts("");
	print_hex("txid      ", txid, 32);
	printf("txid (exp): %s\n", txid_exp);

	free(rawtx);
	txin_destroy(&ins[0]);
	txout_destroy(&outs[0]);
	txout_destroy(&outs[1]);

    return 0;
}
