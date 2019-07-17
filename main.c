/*
 * main.c
 *
 *  Created on: 2019 Jun 14 23:32:15
 *  Author: A79031
 */




#include <DAVE.h>                 //Declarations from DAVE Code Generation (includes SFR declaration)
#include <stdio.h>
#include "circular_buffer.h"
#include "optiga.h"

/* Define section ----------------------------------------------------------------------------*/
#define PRINT_MENU()		printf(">> Command List:\r\n");																		\
							printf(">>    cmd:       			print the command list\r\n");									\
							printf(">>    who_are_you: 			return the name of the device\r\n");							\
							printf(">>    send_challenge:		create and send a challenge\r\n");								\
							printf(">>    gen_key_pair:			generate key pair\r\n");										\
							printf(">>    gen_AES:				generate AES password\r\n");									\
							printf(">>    send_msg:				Send encrypted message\r\n");									\


#define	MAX_CMD_LEN			10
#define	CMD_TABLE_SIZE		7
#define BOB

/* Local variable-----------------------------------------------------------------------------*/
typedef enum STATE{
	ERROR = -1,
	INIT,
	CHIP_AUTH,
	PROCESS_TERMINAL,
	PROCESS_UART,
	WAIT_FOR_PAYLOAD,
	IDLE
}State;

typedef enum ERR_CODE{
	NO_ERR = 0,
	GENERIC,
	OPTIGA_INIT_ERR,
	CHIP_AUH_ERR,
	INVALID_CMD,
	VERIFY_SIGN_ERR,
	CREATE_SIGN_ERR,
	GEN_KEY_ERR,
	CREATE_CHALLENGE_ERR
}ErrorCode;

typedef struct{
	char const *cmd_name;
	ErrorCode (*function)(void);
}command_t;

typedef struct{
	uint8_t chip_auth_count;
	uint8_t peer_auth_count;
	bool peer_authen;
	bool chip_authen;
}sec_count_t;


/* Optiga section */
uint8_t chip_cert[LENGTH_OPTIGA_CERT];
uint16_t chip_cert_size = LENGTH_OPTIGA_CERT;
uint8_t chip_pubkey[LENGTH_PUB_KEY_NISTP256];
uint16_t chip_pubkey_size = LENGTH_PUB_KEY_NISTP256;
uint16_t chip_cert_oid = eDEVICE_PUBKEY_CERT_IFX;
uint16_t chip_privkey_oid = eFIRST_DEVICE_PRIKEY_1;

/*application section*/
uint8_t my_challenge[32];
uint8_t my_challenge_length = 32;
uint8_t my_digest[32] =  {0};
uint8_t my_digest_length = 32;
uint8_t my_signature [70]; //To store the signature generated
uint16_t my_signature_length = 70;
uint8_t my_aes_key [16] = {0};
uint8_t gen_public_key [68] = {0};
uint16_t gen_public_key_length = sizeof(gen_public_key);
uint32_t byte_received = 0;


#ifdef BOB
/*Alice section*/
uint8_t peer_cert[LENGTH_OPTIGA_CERT] = { 	0x30, 0x82, 0x01, 0xbc, 0x30, 0x82, 0x01, 0x62, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x77,
											0xc0, 0x2e, 0x88, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
											0x72, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21,
											0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
											0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41,
											0x47, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0a, 0x4f, 0x50, 0x54, 0x49,
											0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
											0x22, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41,
											0x28, 0x54, 0x4d, 0x29, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x58, 0x20, 0x43, 0x41, 0x20,
											0x31, 0x30, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38, 0x33, 0x31, 0x31, 0x32, 0x30,
											0x39, 0x33, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x37, 0x30, 0x38, 0x33, 0x31, 0x31, 0x32, 0x30, 0x39,
											0x33, 0x31, 0x5a, 0x30, 0x00, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
											0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
											0x5f, 0xbf, 0x43, 0x0b, 0xc6, 0x64, 0x07, 0x95, 0x12, 0x86, 0x55, 0x2c, 0x07, 0x89, 0x4f, 0xda,
											0xc5, 0x32, 0x52, 0x7c, 0xf1, 0xc5, 0xeb, 0x0a, 0xc2, 0x64, 0x50, 0xe4, 0x8d, 0xee, 0xf3, 0x58,
											0x41, 0xbb, 0xd7, 0x81, 0x2b, 0x2a, 0x3d, 0x80, 0x03, 0x18, 0x8f, 0xc9, 0x0d, 0xda, 0x5c, 0xd5,
											0xc9, 0xc7, 0x09, 0x43, 0x84, 0x31, 0x1a, 0x44, 0x39, 0x44, 0xf2, 0x50, 0x33, 0xa1, 0xd4, 0xa4,
											0xa3, 0x58, 0x30, 0x56, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
											0x03, 0x02, 0x00, 0x80, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
											0x30, 0x00, 0x30, 0x15, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0e, 0x30, 0x0c, 0x30, 0x0a, 0x06,
											0x08, 0x2a, 0x82, 0x14, 0x00, 0x44, 0x01, 0x14, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
											0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xca, 0x05, 0x33, 0xd7, 0x4f, 0xc4, 0x7f, 0x09, 0x49, 0xfb,
											0xdb, 0x12, 0x25, 0xdf, 0xd7, 0x97, 0x9d, 0x41, 0x1e, 0x15, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
											0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xf0, 0x23,
											0x7a, 0x18, 0x69, 0xda, 0x19, 0xc4, 0xcb, 0x93, 0x7f, 0xea, 0x4f, 0x99, 0x5b, 0x6f, 0x51, 0x7c,
											0x91, 0x71, 0xfb, 0xbe, 0xdd, 0xd3, 0x4c, 0xb0, 0x58, 0xa3, 0x40, 0xf3, 0xeb, 0x2c, 0x02, 0x20,
											0x24, 0xcd, 0x32, 0x00, 0x12, 0x8d, 0x1d, 0x76, 0x37, 0x13, 0x92, 0x3e, 0x4b, 0xf6, 0x74, 0x64,
											0x30, 0x03, 0xd0, 0x1c, 0xa1, 0xdf, 0x61, 0xdc, 0xe7, 0x62, 0x6c, 0xf9, 0xad, 0x5d, 0x40, 0xf7 };

uint16_t 	peer_cert_size = LENGTH_OPTIGA_CERT;
uint8_t 	peer_pubkey[LENGTH_PUB_KEY_NISTP256 + 3];
uint16_t 	peer_pubkey_size = LENGTH_PUB_KEY_NISTP256;
uint8_t 	peer_signature[LENGTH_SIGNATURE] = {0};
uint8_t 	peer_digest[32] = {0};
uint8_t 	peer_gen_public_key [68] = {0};
uint8_t 	plain_text[16] = "Hi alice!\r\n";
uint8_t 	cipher_txt[16];
uint8_t 	peer_plain_text[16];
uint8_t 	peer_cipher_txt[16];
#else
/*Alice section*/
uint8_t peer_cert[LENGTH_OPTIGA_CERT] = { 	0x30, 0x82, 0x01, 0xbb, 0x30, 0x82, 0x01, 0x62, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x2c,
											0x61, 0x03, 0xe3, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
											0x72, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x21,
											0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x18, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f,
											0x6e, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f, 0x67, 0x69, 0x65, 0x73, 0x20, 0x41,
											0x47, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0a, 0x4f, 0x50, 0x54, 0x49,
											0x47, 0x41, 0x28, 0x54, 0x4d, 0x29, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
											0x22, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x65, 0x6f, 0x6e, 0x20, 0x4f, 0x50, 0x54, 0x49, 0x47, 0x41,
											0x28, 0x54, 0x4d, 0x29, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x58, 0x20, 0x43, 0x41, 0x20,
											0x31, 0x30, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x38, 0x33, 0x31, 0x31, 0x32, 0x30,
											0x39, 0x33, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x37, 0x30, 0x38, 0x33, 0x31, 0x31, 0x32, 0x30, 0x39,
											0x33, 0x31, 0x5a, 0x30, 0x00, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
											0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
											0xff, 0x4e, 0x34, 0xf4, 0x1b, 0xfe, 0xee, 0xba, 0x74, 0x4f, 0x5d, 0x84, 0x75, 0x3a, 0xa1, 0x4c,
											0x45, 0x97, 0xfd, 0x8a, 0x99, 0x94, 0xd6, 0x2a, 0xdb, 0x00, 0x2a, 0x09, 0x3e, 0x3f, 0xa2, 0x5c,
											0x22, 0x0c, 0x2c, 0x26, 0x65, 0x68, 0x58, 0xce, 0xe1, 0x4d, 0x4e, 0xf9, 0xba, 0x7b, 0x94, 0x69,
											0xfc, 0x9a, 0x60, 0xea, 0x90, 0xb6, 0x09, 0x7c, 0xd4, 0x8f, 0xc3, 0x1a, 0xf8, 0xc7, 0xd8, 0xdd,
											0xa3, 0x58, 0x30, 0x56, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
											0x03, 0x02, 0x00, 0x80, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
											0x30, 0x00, 0x30, 0x15, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0e, 0x30, 0x0c, 0x30, 0x0a, 0x06,
											0x08, 0x2a, 0x82, 0x14, 0x00, 0x44, 0x01, 0x14, 0x01, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
											0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xca, 0x05, 0x33, 0xd7, 0x4f, 0xc4, 0x7f, 0x09, 0x49, 0xfb,
											0xdb, 0x12, 0x25, 0xdf, 0xd7, 0x97, 0x9d, 0x41, 0x1e, 0x15, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
											0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x0b, 0xeb, 0x87,
											0x78, 0xe5, 0xa4, 0x4e, 0xfe, 0x28, 0x94, 0xca, 0x09, 0x8f, 0x57, 0xdd, 0xb9, 0xc6, 0x81, 0x54,
											0xe6, 0x0e, 0x39, 0xd7, 0x33, 0xaf, 0xd2, 0x56, 0x49, 0xff, 0xf0, 0x1a, 0x69, 0x02, 0x20, 0x30,
											0x1a, 0x84, 0xa1, 0xf4, 0xad, 0xc6, 0x83, 0x7d, 0x49, 0xdb, 0xaf, 0xd5, 0xe6, 0x9f, 0x49, 0x6d,
											0x55, 0xd7, 0xe1, 0x6c, 0xc2, 0x3d, 0x62, 0x08, 0x3c, 0xab, 0x16, 0xa8, 0x65, 0xf2, 0xfe};

uint16_t 	peer_cert_size = LENGTH_OPTIGA_CERT;
uint8_t 	peer_pubkey[LENGTH_PUB_KEY_NISTP256 + 3];
uint16_t 	peer_pubkey_size = LENGTH_PUB_KEY_NISTP256;
uint8_t 	peer_signature[LENGTH_SIGNATURE] = {0};
uint8_t 	peer_digest[32] = {0};
uint8_t 	peer_gen_public_key [68] = {0};

uint8_t plain_text[16] = "Hi bob!\r\n";
uint8_t cipher_txt[16];
uint8_t 	peer_plain_text[16];
uint8_t 	peer_cipher_txt[16];
#endif

/*Generic section*/
uint8_t 	cmd_uart_ard[1024] = {0};
uint16_t 	cmd_uart_ard_indx = 0;
optiga_lib_status_t optiga_status;
uint8_t c_debug;
uint8_t c_ard;
cir_buff my_buff;
uint8_t cmd_found = 0;
State state = INIT;
ErrorCode err_code = NO_ERR;
sec_count_t my_count;

/* Function prototype -------------------------------------------------------------------------*/
static void PrintBytes(uint8_t * ptr, uint32_t length);
static ErrorCode ProcessCommand(void);
static void ProccessCommandFromUartARD(void);
ErrorCode PrintMenu(void);
ErrorCode CreateSignature(void);
ErrorCode CreateDigest(void);
ErrorCode WhoAreYou(void);
ErrorCode AuthenticatePeer(void);
ErrorCode GeneateAESKey(void);
ErrorCode GenerateKeyPair(void);
ErrorCode SendEncryptMessage(void);
ErrorCode DecryptMessage(void);

command_t const cmd_table[CMD_TABLE_SIZE] = {
		{"cmd",				PrintMenu,},
		{"who_are_you",		WhoAreYou,},
		{"gen_key_pair",	GenerateKeyPair,},
		{"send_challenge", 	CreateDigest,},
		{"gen_AES", 		GeneateAESKey,},
		{"send_msg", 		SendEncryptMessage,},
		{NULL,				NULL},
};

/* main ---------------------------------------------------------------------------------------*/
int main(void)
{
  DAVE_STATUS_t status;
  status = DAVE_Init();           /* Initialization of DAVE APPs  */

  if(status != DAVE_STATUS_SUCCESS)
  {
    /* Placeholder for error handler code. The while loop below can be replaced with an user error handler. */
    XMC_DEBUG("DAVE APPs initialization failed\n");

    while(1U)
    {

    }
  }

  peer_pubkey[0] = 0x03;
  peer_pubkey[1] = 0x42;
  peer_pubkey[2] = 0x00;

  my_count.chip_auth_count = 3;
  my_count.peer_auth_count = 3;
  my_count.peer_authen = false;
  my_count.chip_authen = false;

  if(UART_Transmit(&UART_ARD, (uint8_t *)"hello evee\r\n", 12) == UART_STATUS_SUCCESS){
	  while(UART_ARD.runtime->tx_busy) {
	  }
  }
  InitCirBuff(&my_buff);
  UART_Receive(&UART_DBG, &c_debug, 1);


  printf("\r\n\r\n\r\n");
#ifdef BOB
  printf("hello from Bob\r\n");
#else
  printf("hello from Alice\r\n");
#endif

  PRINT_MENU();

  while(1U)
  {
	  switch(state){
	  case INIT:
		  if (OPTIGA_LIB_SUCCESS != OptigaInit()){
			  printf(">> optiga_init error\r\n");
			  state = ERROR;
			  err_code = OPTIGA_INIT_ERR;
			  break;
		  }
		  printf(">> optiga init complete\r\n");
		  state = CHIP_AUTH;
		  break;

	  case CHIP_AUTH:
		  printf(">> authenticating in progress, please wait\r\n");

		  if (OPTIGA_LIB_SUCCESS != GetChipCertificate(chip_cert_oid, chip_cert, &chip_cert_size)){
			  printf("> get certificate error\r\n");
			  state = ERROR;
			  err_code = CHIP_AUH_ERR;
			  break;
		  }
		  printf(">> chip certificate: \r\n");
		  PrintBytes(chip_cert, chip_cert_size);

		  if(CRYPTO_LIB_OK != GetPublicKey(chip_cert, chip_cert_size, chip_pubkey, &chip_pubkey_size))
		  {
			  printf(">> get public key error\r\n");
			  state = ERROR;
			  err_code = CHIP_AUH_ERR;
			  break;
		  }
		  printf(">> chip pub key: \r\n");
		  PrintBytes(chip_pubkey, chip_pubkey_size);

		  if(OPTIGA_LIB_SUCCESS != AuthenticateChip(chip_pubkey, chip_pubkey_size, chip_privkey_oid))
		  {
			  printf(">> authenticate fail\r\n");
			  state = ERROR;
			  err_code = CHIP_AUH_ERR;
			  break;
		  }
		  printf(">> authenticated\r\n");
		  my_count.chip_authen = true;
		  state = IDLE;
		  break;

	  case IDLE:
		  UART_Receive(&UART_ARD, cmd_uart_ard, 2);
		  break;

	  case PROCESS_TERMINAL:
		  err_code = ProcessCommand();
		  if(NO_ERR != err_code)
			  state = ERROR;
		  else
			  state = IDLE;
		  break;

	  case PROCESS_UART:
		  ProccessCommandFromUartARD();
		  cmd_uart_ard_indx = 0;
		  memset(cmd_uart_ard, 0, 1024);
		  break;
	  case WAIT_FOR_PAYLOAD:
		  break;
	  case ERROR:
		  switch(err_code){
		  case NO_ERR:
			  //do nothing
			  state = IDLE;
			  break;
		  case GENERIC:
		  case OPTIGA_INIT_ERR:
		  case CHIP_AUH_ERR:
			  OptigaXErrorHandler();
			  state = INIT;
			  break;
		  case INVALID_CMD:
		  case VERIFY_SIGN_ERR:
		  case CREATE_SIGN_ERR:
		  case CREATE_CHALLENGE_ERR:
		  default:
			  state = IDLE;
			  break;
		  }
		  err_code = NO_ERR;//Reset error code to no error
		  break;

	  default:
		  break;
	  }
  }
}

/* functions ---------------------------------------------------------------------------------------*/
static void PrintBytes(uint8_t * ptr, uint32_t length)
{

	uint32_t i = 0;
	uint8_t line_count = 0;
	for(;i < length; i++) {
		printf("0x%02x, ",ptr[i]);
		line_count++;
		if(line_count == 16) {
			printf("\r\n");
			line_count = 0;
		}
	}

	printf("\r\n");
}


static ErrorCode ProcessCommand(void)
{
	char cmd[BUFF_SIZE] = {0};
	uint8_t i = 0;
	bool cmd_found = false;

	do{
		PopCirBuff(&my_buff, &cmd[i]);
		i++;
	}while(cmd[i - 1] != '\r');


	cmd[i - 1] = '\0';
	PopCirBuff(&my_buff, &cmd[i]);//pop the '\n' out of the buffer

	for(i = 0; cmd_table[i].cmd_name != NULL; i++){
		if(strcmp(cmd_table[i].cmd_name, cmd) == 0){
			cmd_found = true;
			break;
		}
	}

	if(cmd_found)
		return cmd_table[i].function();
	else{
		printf(">> invalid command\r\n");
		return INVALID_CMD;
	}

	return NO_ERR;
}


ErrorCode PrintMenu(void)
{
	PRINT_MENU();
	return NO_ERR;
}

ErrorCode CreateSignature(void)
{
	printf(">> creating a signature... \r\n");
	optiga_status = optiga_crypt_ecdsa_sign( peer_digest, 32, OPTIGA_KEY_STORE_ID_E0F0, my_signature, &my_signature_length);
	if(OPTIGA_LIB_SUCCESS !=  optiga_status){
	  printf(">> ecdsa fail\r\n");
	  return CREATE_SIGN_ERR;
	}
	return NO_ERR;
}


ErrorCode CreateDigest(void)
{
	optiga_status = OptigaXCryptoGetRandom(my_challenge_length, my_challenge);
	if(OPTIGA_LIB_SUCCESS !=  optiga_status){
		printf(">> get ramdom number fail\r\n");
		return CREATE_CHALLENGE_ERR;
	}

	optiga_status = OptigaXCryptoGetHash(my_digest, my_challenge, 32);
	if(OPTIGA_LIB_SUCCESS !=  optiga_status){
		printf(">> get hash fail\r\n");
		return CREATE_CHALLENGE_ERR;
	}
	printf(">> my digest: \r\n");
	PrintBytes(my_digest, 32);

	printf(">> sending digest...  \r\n");
	cmd_uart_ard[0] = 0x02;
	cmd_uart_ard[1] = 0x20;
	memcpy(&cmd_uart_ard[2], my_digest, 32);

	if(UART_Transmit(&UART_ARD, cmd_uart_ard, 32 + 2) == UART_STATUS_SUCCESS){
		  while(UART_ARD.runtime->tx_busy) {
		  }
	  }
	return NO_ERR;
}

ErrorCode WhoAreYou(void)
{
#ifdef BOB
	printf(">> Bob\r\n");
#else
	printf(">> Alice\r\n");
#endif
	return NO_ERR;
}


ErrorCode AuthenticatePeer(void)
{


	if(CRYPTO_LIB_OK != GetPublicKey(peer_cert, peer_cert_size, &peer_pubkey[3], &peer_pubkey_size))
	{
		printf(">> get public key error\r\n");
		return VERIFY_SIGN_ERR;
	}
#ifdef BOB
	printf(">> alice pub key: \r\n");
#else
	printf(">> bob pub key: \r\n");
#endif
	PrintBytes(peer_pubkey, peer_pubkey_size + 3);

	if(CRYPTO_LIB_OK != VerifyEccSignature(	&peer_pubkey[3], peer_pubkey_size,
											peer_signature, LENGTH_SIGNATURE,
											my_digest, LENGTH_SHA256)){
		printf(">> signature verification fail\r\n");
		return VERIFY_SIGN_ERR;
	}

	printf("signature verification ok\r\n");

	return NO_ERR;
}

ErrorCode GeneateAESKey(void)
{
	if(CRYPTO_LIB_OK != OptigaGenerateAESKey( peer_gen_public_key, sizeof(peer_gen_public_key), my_aes_key, sizeof(my_aes_key))){
		printf(">> Generate key error");
		return GEN_KEY_ERR;
	}
	printf(">> generated public key: \r\n");
	PrintBytes(gen_public_key, gen_public_key_length);

	printf(">> generated aes key: \r\n");
	PrintBytes(my_aes_key, 16);
	printf(">> IN THIS SITUALTION, IT SHOWS THAT BOTH DEVICES HAVE THE SAME KEY WITHOUT EXCHANGING THE KEY\r\n");
	printf(">> IN REAL APPLICATION, WE DONT SHARE THIS KEY!!!!!!!!!!!\r\n");
#if 0 // Test AES
	mbedtls_aes_context aes;
	char plain[16] = "hello world\r\n";
	char cipher[16];
	char cipher_dec[16];

	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, my_aes_key, 16*8);
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plain, cipher);
	mbedtls_aes_free( &aes );

	printf("plain: \r\n");
	PrintBytes(plain, 16);

	printf("cipher: \r\n");
	PrintBytes(cipher, 16);

	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, my_aes_key, 16*8);
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, cipher, cipher_dec);
	mbedtls_aes_free( &aes );

	printf("cipher: \r\n");
	PrintBytes(cipher_dec, 16);

#endif

	return NO_ERR;
}

ErrorCode GenerateKeyPair(void)
{
	optiga_key_id_t optiga_key_id;
	optiga_key_id = OPTIGA_SESSION_ID_E100;
	optiga_status = optiga_crypt_ecc_generate_keypair(OPTIGA_ECC_NIST_P_256,
													  (uint8_t)OPTIGA_KEY_USAGE_KEY_AGREEMENT,
													  FALSE,
													  &optiga_key_id,
													  gen_public_key,
													  &gen_public_key_length);

	if (OPTIGA_LIB_SUCCESS != optiga_status)
	{
		return GEN_KEY_ERR;
	}
	#ifdef BOB
		printf("key generated by bob: \r\n");
	#else
		printf("key generated by alice: \r\n");
	#endif
	PrintBytes(gen_public_key, gen_public_key_length);
	cmd_uart_ard[0] = 0x04;
	cmd_uart_ard[1] = 68;
	memcpy(&cmd_uart_ard[2], gen_public_key, 68);

	if(UART_Transmit(&UART_ARD, cmd_uart_ard, 68 + 2) == UART_STATUS_SUCCESS){
		while(UART_ARD.runtime->tx_busy) {
			}
	}
	return NO_ERR;
}

ErrorCode SendEncryptMessage(void)
{
	mbedtls_aes_context aes;

	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_enc(&aes, my_aes_key, 16*8);
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char*)plain_text, cipher_txt);
	mbedtls_aes_free( &aes );

	cmd_uart_ard[0] = 0x05;
	cmd_uart_ard[1] = 16;
	memcpy(&cmd_uart_ard[2], cipher_txt, 16);

	if(UART_Transmit(&UART_ARD, cmd_uart_ard, 16 + 2) == UART_STATUS_SUCCESS){
		while(UART_ARD.runtime->tx_busy) {
			}
	}

	printf(">> plain message: %s\r\n", plain_text);

	printf("cipher message: %s\r\n", cipher_txt);
	return NO_ERR;
}
ErrorCode DecryptMessage(void)
{
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec(&aes, my_aes_key, 16*8);
	mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, peer_cipher_txt, peer_plain_text);
	mbedtls_aes_free( &aes );


	return NO_ERR;
}

static void ProccessCommandFromUartARD(void)
{
	switch(cmd_uart_ard[0]){
	case 0x02://receive digest
#ifdef BOB
		printf("receive alice digest---------------------------------------------------------\r\n");
#else
		printf("receive bob digest---------------------------------------------------------\r\n");
#endif
		memcpy(peer_digest, &cmd_uart_ard[2], 32);
#ifdef BOB
		printf(">> alice's digest: \r\n");
#else
		printf(">> bob's digest: \r\n");
#endif
		PrintBytes(peer_digest, 32);
		err_code = CreateSignature();
		if(NO_ERR == err_code){
			state = IDLE;
#ifdef BOB
			printf(">> signature sent to alice: \r\n");
#else
			printf(">> signature sent to bob: \r\n");
#endif
			PrintBytes(my_signature, 70);

			cmd_uart_ard[0] = 0x03;
			cmd_uart_ard[1] = 0x46;
			memcpy(&cmd_uart_ard[2], my_signature, 70);

			if(UART_Transmit(&UART_ARD, cmd_uart_ard, 70 + 2) == UART_STATUS_SUCCESS){
				  while(UART_ARD.runtime->tx_busy) {
				  }
			  }
		}
		else{
			state = ERROR;
			return;
		}
		break;
	case 0x03://receive challenge;
		memcpy(peer_signature, &cmd_uart_ard[2], 70);
#ifdef BOB
		printf(">> Received signature from Alice: \r\n");
#else
		printf(">> Received signature from Bob: \r\n");
#endif
		PrintBytes(peer_signature, my_signature_length);
		printf(">> Verifying signature... \r\n");
		err_code = AuthenticatePeer();
		if(NO_ERR == err_code){
			printf(">> verified\r\n");
			my_count.peer_authen = true;
			state = IDLE;
		}
		else{
			printf(">> wrong signature\r\n");
			state = ERROR;
			my_count.peer_authen = false;
			return;
		}

		break;
	case 0x04:
		memcpy(peer_gen_public_key, &cmd_uart_ard[2], 80);
#ifdef BOB
		printf(">> Received pub key from Alice: \r\n");
#else
		printf(">> Received pub key from Bob: \r\n");
#endif
		PrintBytes(peer_gen_public_key, gen_public_key_length);
		break;
	case 0x05:
		memcpy(peer_cipher_txt, &cmd_uart_ard[2], 16);
		DecryptMessage();
#ifdef BOB
		printf(">> message from alice: \r\n");
#else
		printf(">> message from bob: \r\n");
#endif
		printf(">> cipher message: %s\r\n", peer_cipher_txt);
		printf(">> plain message: %s\r\n", peer_plain_text);
		break;
	default:
		state = IDLE;
		err_code = NO_ERR;
		break;
	}
	return;
}

/*UART receive callback*/
void UARTReceiveCallback(void)
{
	PushCirBuff(&my_buff, c_debug);
	if(c_debug == '\n')
		state = PROCESS_TERMINAL;
	UART_Receive(&UART_DBG, &c_debug, 1);
}

void UART_ARD_TX_Callback(void)
{
}

void UART_ARD_RX_Callback(void)
{
	if(state == IDLE){
		byte_received = cmd_uart_ard[1];
		if(byte_received == 0){
				state = PROCESS_UART;
		}else{
			state = WAIT_FOR_PAYLOAD;
			UART_Receive(&UART_ARD, &cmd_uart_ard[2], byte_received);
		}
	}
	else{
		state = PROCESS_UART;
	}
}

/* Implement printf------------------------------------------------------------------*/
int _write(int file, uint8_t *buf, int nbytes)
{
    if(UART_Transmit(&UART_DBG, buf, nbytes) == UART_STATUS_SUCCESS) {
       while(UART_DBG.runtime->tx_busy) {
        }
    }
    return nbytes;
}

/* This "wires" the getchar function to receive from UART_0 */
int _read(int file, uint8_t *buf, int nbytes)
{
    if(UART_Receive(&UART_DBG, buf, 1) != UART_STATUS_SUCCESS) {
      nbytes = 0;
    } else {
      nbytes = 1;
    }
	return nbytes;
}





