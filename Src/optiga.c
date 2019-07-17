

#include "optiga.h"

optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_0,NULL,NULL, OPTIGA_COMMS_SUCCESS};



optiga_lib_status_t OptigaXCryptoGetHash(uint8_t * digest, uint8_t * challenge, uint8_t length);
static optiga_lib_status_t  pal_crypt_verify_signature(const uint8_t* p_pubkey, uint16_t pubkey_size,
		                                        const uint8_t* p_signature, uint16_t signature_size,
									                  uint8_t* p_digest, uint16_t digest_size);


int32_t VerifyEccSignature(const uint8_t* p_pubkey, uint16_t pubkey_size,
                                      const uint8_t* p_signature, uint16_t signature_size,
                                            uint8_t* p_digest, uint16_t digest_size);
											
											
int32_t OptigaInit(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do
	{
		status = optiga_util_open_application(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			XMC_DEBUG( ("Failure: CmdLib_OpenApplication(): 0x%04X\n\r", status) );
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	return status;
}

int32_t OptigaDeinit(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;
	//Close IFX I2C Protocol and switch off the security chip
	status = optiga_comms_close(&optiga_comms);
	if(OPTIGA_LIB_SUCCESS != status)
	{
	}

	printf("Device closed\n");
	return status;
}


void OptigaXErrorHandler(void)
{
	if (OPTIGA_LIB_SUCCESS != OptigaDeinit())
			printf("optiga_deinit error\r\n");
}

optiga_lib_status_t OptigaXCryptoGetRandom(uint8_t length, uint8_t * random)
{
	optiga_lib_status_t optiga_status = OPTIGA_LIB_ERROR;

	optiga_status = optiga_crypt_random(OPTIGA_RNG_TYPE_TRNG, random, length);

	return optiga_status;
}


optiga_lib_status_t OptigaXCryptoGetHash(uint8_t * digest, uint8_t * challenge, uint8_t length)
{

	optiga_lib_status_t optiga_status = OPTIGA_LIB_ERROR;

	uint8_t hash_context_buffer [130];

	optiga_hash_context_t hash_context;
	hash_data_from_host_t hash_data_host;

	hash_context.context_buffer = hash_context_buffer;
	hash_context.context_buffer_length = sizeof(hash_context_buffer);
	hash_context.hash_algo = OPTIGA_HASH_TYPE_SHA_256;

	//Hash start
	optiga_status = optiga_crypt_hash_start(&hash_context);
	if(optiga_status != OPTIGA_LIB_SUCCESS)
	{
		return optiga_status;
	}

	//Hash update
	hash_data_host.buffer = challenge;
	hash_data_host.length = length;
	optiga_status = optiga_crypt_hash_update(	&hash_context,
												// OPTIGA_CRYPT_OID_DATA stands for OID
												OPTIGA_CRYPT_HOST_DATA,
												&hash_data_host);
	if(optiga_status != OPTIGA_LIB_SUCCESS)
		return optiga_status;

	// hash finalize
	optiga_status = optiga_crypt_hash_finalize(&hash_context, digest);
	if(optiga_status != OPTIGA_LIB_SUCCESS)
		return optiga_status;

	return optiga_status;
}


optiga_lib_status_t GetChipCertificate(uint16_t cert_oid, uint8_t* p_cert, uint16_t* p_cert_size)
{
	int32_t status  = (int32_t)OPTIGA_LIB_ERROR;
	// We might need to modify a certificate buffer pointer
	uint8_t tmp_cert[LENGTH_OPTIGA_CERT];
	uint8_t* p_tmp_cert_pointer = tmp_cert;

	do
	{
		// Sanity check
		if ((NULL == p_cert) || (NULL == p_cert_size) ||
			(0 == cert_oid) || (0 == *p_cert_size))
		{
			break;
		}

		//Get end entity device certificate
		status = optiga_util_read_data(cert_oid, 0, p_tmp_cert_pointer, p_cert_size);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			break;
		}

		// Refer to the Solution Reference Manual (SRM) v1.35 Table 30. Certificate Types
		switch (p_tmp_cert_pointer[0])
		{
		/* One-Way Authentication Identity. Certificate DER coded The first byte
		*  of the DER encoded certificate is 0x30 and is used as Tag to differentiate
		*  from other Public Key Certificate formats defined below.
		*/
		case 0x30:
			/* The certificate can be directly used */
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* TLS Identity. Tag = 0xC0; Length = Value length (2 Bytes); Value = Certificate Chain
		 * Format of a "Certificate Structure Message" used in TLS Handshake
		 */
		case 0xC0:
			/* There might be a certificate chain encoded.
			 * For this example we will consider only one certificate in the chain
			 */
			p_tmp_cert_pointer = p_tmp_cert_pointer + 9;
			*p_cert_size = *p_cert_size - 9;
			memcpy(p_cert, p_tmp_cert_pointer, *p_cert_size);
			status = OPTIGA_LIB_SUCCESS;
			break;
		/* USB Type-C identity
		 * Tag = 0xC2; Length = Value length (2 Bytes); Value = USB Type-C Certificate Chain [USB Auth].
		 * Format as defined in Section 3.2 of the USB Type-C Authentication Specification (SRM)
		 */
		case 0xC2:
		// Not supported for this example
		// Certificate type isn't supported or a wrong tag
		default:
			break;
		}

	}while(FALSE);

	return status;
}

optiga_lib_status_t GetPublicKey(const uint8_t* p_cert, uint16_t cert_size,
							     uint8_t* p_pubkey, uint16_t* p_pubkey_size)
{
    int32_t status  = (int32_t)CRYPTO_LIB_ERROR;
    int32_t ret;
    mbedtls_x509_crt mbedtls_cert;
    size_t pubkey_size = 0;
    // We know, that we will work with ECC
    mbedtls_ecp_keypair * mbedtls_keypair = NULL;

    do
    {
        if((NULL == p_cert) || (NULL == p_pubkey) || (NULL == p_pubkey_size))
        {
        	status = (int32_t)CRYPTO_LIB_NULL_PARAM;
            break;
        }

        //Check for length equal to zero
        if( (0 == cert_size) || (0 == *p_pubkey_size))
        {
        	status = (int32_t)CRYPTO_LIB_LENZERO_ERROR;
            break;
        }

        //Initialise certificates
        mbedtls_x509_crt_init(&mbedtls_cert);

        if ( (ret = mbedtls_x509_crt_parse_der(&mbedtls_cert, p_cert, cert_size)) != 0 )
		{
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
		}

        mbedtls_keypair = (mbedtls_ecp_keypair* )mbedtls_cert.pk.pk_ctx;
        if ( (ret = mbedtls_ecp_point_write_binary(&mbedtls_keypair->grp, &mbedtls_keypair->Q,
        		                                   MBEDTLS_ECP_PF_UNCOMPRESSED, &pubkey_size,
												   p_pubkey, *p_pubkey_size)) != 0 )
        {
			status = (int32_t)CRYPTO_LIB_CERT_PARSE_FAIL;
			break;
        }
        *p_pubkey_size = pubkey_size;

        status =   CRYPTO_LIB_OK;
    }while(FALSE);

    return status;
}



optiga_lib_status_t AuthenticateChip(uint8_t* p_pubkey, uint16_t pubkey_size, uint16_t privkey_oid)
{
    int32_t status  = OPTIGA_LIB_ERROR;
    uint8_t random[LENGTH_CHALLENGE];
    uint8_t signature[LENGTH_SIGNATURE];
    uint16_t signature_size = LENGTH_SIGNATURE;
    uint8_t digest[LENGTH_SHA256];

    do
    {
        //Get PwChallengeLen byte random stream
        status = OptigaXCryptoGetRandom(LENGTH_CHALLENGE, random);
        if(OPTIGA_LIB_SUCCESS != status)
        {
            break;
        }

        status = OptigaXCryptoGetHash(digest, random, LENGTH_CHALLENGE);
        if(OPTIGA_LIB_SUCCESS != status)
        {
        	status = (int32_t)CRYPTO_LIB_VERIFY_SIGN_FAIL;
            break;
        }

		//Sign random with OPTIGA™ Trust X
        status = optiga_crypt_ecdsa_sign(digest, LENGTH_SHA256,
									     privkey_oid,
										 signature, &signature_size);
        if (OPTIGA_LIB_SUCCESS != status)
        {
			// Signature generation failed
            break;
        }

		//Verify the signature on the random number by Security Chip
		status = pal_crypt_verify_signature(p_pubkey, pubkey_size,
				                            signature, signature_size,
											digest, LENGTH_SHA256);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			break;
		}
	} while (FALSE);

    return status;
}

static optiga_lib_status_t  pal_crypt_verify_signature(const uint8_t* p_pubkey, uint16_t pubkey_size,
		                                        const uint8_t* p_signature, uint16_t signature_size,
									                  uint8_t* p_digest, uint16_t digest_size)
{
    int32_t status  = (int32_t)OPTIGA_LIB_ERROR;
    do
    {
        if((NULL == p_pubkey)|| (NULL == p_signature) || (NULL == p_pubkey))
        {
        	status = (int32_t)CRYPTO_LIB_NULL_PARAM;
            break;
        }
        //check if length is equal to zero
        if((0 == digest_size) || (0 == signature_size) || (0 == pubkey_size))
        {
        	status = (int32_t)CRYPTO_LIB_LENZERO_ERROR;
            break;
        }

        status = VerifyEccSignature(p_pubkey, pubkey_size,
									p_signature, signature_size,
									p_digest, digest_size);
    }while(FALSE);
    return status;
}

int32_t VerifyEccSignature(const uint8_t* p_pubkey, uint16_t pubkey_size,
                                      const uint8_t* p_signature, uint16_t signature_size,
                                            uint8_t* p_digest, uint16_t digest_size)
{
    int32_t  status = (int32_t)CRYPTO_LIB_VERIFY_SIGN_FAIL;
    uint8_t   signature_rs[LENGTH_MAX_SIGNATURE];
    size_t    signature_rs_size = LENGTH_MAX_SIGNATURE;
    const uint8_t* p_pk = p_pubkey;

    mbedtls_ecp_group grp;
    // Public Key
    mbedtls_ecp_point Q;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_ecp_point_init( &Q );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_group_init( &grp );

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

    do
    {
        if((NULL == p_pubkey)||(NULL == p_digest)||(NULL == p_signature))
        {
            status = (int32_t)CRYPTO_LIB_NULL_PARAM;
            break;
        }

        //Import the public key
        mbedtls_ecp_point_read_binary(&grp, &Q, p_pk, pubkey_size);

        //Import the signature
        asn1_to_ecdsa_rs(p_signature, signature_size, signature_rs, &signature_rs_size);
        mbedtls_mpi_read_binary(&r, signature_rs, LENGTH_MAX_SIGNATURE/2);
        mbedtls_mpi_read_binary(&s, signature_rs + LENGTH_MAX_SIGNATURE/2, LENGTH_MAX_SIGNATURE/2);

        //Verify generated hash with given public key
        status = mbedtls_ecdsa_verify(&grp, p_digest, digest_size, &Q, &r, &s);

        if ( MBEDTLS_ERR_ECP_VERIFY_FAILED == status)
        {
            status = (int32_t)CRYPTO_LIB_VERIFY_SIGN_FAIL;
            break;
        }

        status = CRYPTO_LIB_OK;
    }while(FALSE);

    return status;
}


optiga_lib_status_t OptigaGenerateAESKey(	uint8_t * peer_pub_key, uint16_t peer_pub_key_size, uint8_t * aes_key, uint8_t aes_size)
{
	optiga_lib_status_t optiga_status;

	optiga_key_id_t optiga_key_id;
	uint8_t label [] = "";
	uint8_t my_challenge[32] = {0};


	public_key_from_host_t peer_public_key_details = {	peer_pub_key,
														peer_pub_key_size,
														OPTIGA_ECC_NIST_P_256};


	optiga_key_id = OPTIGA_SESSION_ID_E100;
	optiga_status = optiga_crypt_ecdh(optiga_key_id,
									  &peer_public_key_details,
									  FALSE,
									  (uint8_t *)&optiga_key_id);
	if (OPTIGA_LIB_SUCCESS != optiga_status)
	{
		return optiga_status;
	}

	optiga_status = optiga_crypt_tls_prf_sha256(optiga_key_id, /* Input secret OID */
												label,
												sizeof(label),
												my_challenge,
												32,
												aes_size,
												TRUE,
												aes_key);

	if(OPTIGA_LIB_SUCCESS != optiga_status)
	{
		return optiga_status;
	}

	return OPTIGA_LIB_SUCCESS;
}
