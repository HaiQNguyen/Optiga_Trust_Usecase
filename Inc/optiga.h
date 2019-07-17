#ifndef _OPTIGA_H_
#define _OPTIGA_H_


#include <DAVE.h>                 //Declarations from DAVE Code Generation (includes SFR declaration)
#include <stdio.h>

#include "optiga/comms/optiga_comms.h"
#include "optiga/optiga_util.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"
#include "optiga/common/AuthLibSettings.h"
#include "optiga/pal/pal_os_timer.h"
#include "optiga/common/MemoryMgmt.h"
#include "optiga/optiga_crypt.h"

#include "ecdsa_utils.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

// MAximum size of the ssignature (for P256 0x40)
#define LENGTH_MAX_SIGNATURE			0x40
//size of public key for NIST-P256
#define LENGTH_PUB_KEY_NISTP256     	0x41
//Length of R and S vector
#define LENGTH_RS_VECTOR            	0x40
//Length of maximum additional bytes to encode sign in DER
#define MAXLENGTH_SIGN_ENCODE       	0x06
//Length of Signature
#define LENGTH_SIGNATURE            	(LENGTH_RS_VECTOR + MAXLENGTH_SIGN_ENCODE)
// Length of the requested challenge
#define LENGTH_CHALLENGE				32
// Length of SH256
#define LENGTH_SHA256					32
//size of end entity certificate of OPTIGA™ Trust X
#define LENGTH_OPTIGA_CERT         		512


///Requested operation completed without any error
#define CRYPTO_LIB_OK                               OPTIGA_LIB_SUCCESS
//Null parameter(s)
#define CRYPTO_LIB_NULL_PARAM                       0x80003001
//Certificate parse failure
#define CRYPTO_LIB_CERT_PARSE_FAIL                  (CRYPTO_LIB_NULL_PARAM + 1)
//Signature Verification failure
#define CRYPTO_LIB_VERIFY_SIGN_FAIL                 (CRYPTO_LIB_NULL_PARAM + 2)
//SHA256 generation failure
#define CRYPTO_LIB_SHA256_FAIL                      (CRYPTO_LIB_NULL_PARAM + 3)
//Length of input is zero
#define CRYPTO_LIB_LENZERO_ERROR                    (CRYPTO_LIB_NULL_PARAM + 4)
//Length of Parameters are zero
#define CRYPTO_LIB_LENMISMATCH_ERROR                (CRYPTO_LIB_NULL_PARAM + 5)
//Memory allocation failure
#define CRYPTO_LIB_MEMORY_FAIL                      (CRYPTO_LIB_NULL_PARAM + 6)
//Insufficient memory
#define CRYPTO_LIB_INSUFFICIENT_MEMORY              (CRYPTO_LIB_NULL_PARAM + 7)
//Generic error condition
#define CRYPTO_LIB_ERROR                            0xF1743903



void OptigaXErrorHandler(void);
int32_t OptigaInit(void);
int32_t OptigaDeinit(void);
optiga_lib_status_t GetChipCertificate(uint16_t cert_oid, uint8_t* p_cert, uint16_t* p_cert_size);
optiga_lib_status_t GetPublicKey(const uint8_t* p_cert, uint16_t cert_size,
							     uint8_t* p_pubkey, uint16_t* p_pubkey_size);
optiga_lib_status_t AuthenticateChip(uint8_t* p_pubkey, uint16_t pubkey_size, uint16_t privkey_oid);
optiga_lib_status_t OptigaXCryptoGetRandom(uint8_t length, uint8_t * random);
optiga_lib_status_t OptigaXCryptoGetHash(uint8_t * digest, uint8_t * challenge, uint8_t length);

int32_t VerifyEccSignature(const uint8_t* p_pubkey, uint16_t pubkey_size,
                                      const uint8_t* p_signature, uint16_t signature_size,
                                            uint8_t* p_digest, uint16_t digest_size);
optiga_lib_status_t OptigaGenerateAESKey(	uint8_t * peer_pub_key, uint16_t peer_pub_key_size, uint8_t * aes_key, uint8_t aes_size);

#endif
