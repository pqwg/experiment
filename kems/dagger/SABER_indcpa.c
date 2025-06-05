#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.h"
#include "fips202.h"
#include "SABER_params.h"
#include "randombytes.h"

/*-----------------------------------------------------------------------------------
	This routine generates a=[Matrix K x K] of 256-coefficient polynomials 
-------------------------------------------------------------------------------------*/

#define h1 (0x1U << (SABER_EQ - SABER_EP - 1)) //2^(EQ-EP-1)

#define h2 ( (1<<(SABER_EP-2)) - (1<<(SABER_EP-SABER_ET-1)) + (1<<(SABER_EQ-SABER_EP-1)) )

void InnerProd(uint16_t pkcl[SABER_K][SABER_N],uint16_t skpv[SABER_K][SABER_N],uint16_t mod,uint16_t res[SABER_N], uint16_t buf[512], uint16_t* const tc_buf);
void MatrixVectorMul(polyvec *a, uint16_t skpv[SABER_K][SABER_N], uint16_t res[SABER_K][SABER_N], uint16_t mod, int16_t transpose, uint16_t buf[512], uint16_t* const tc_buf);

void POL2MSG(uint16_t *message_dec_unpacked, unsigned char *message_dec);

#define ONE_VECTOR (13*SABER_N/8)
#define BYTE_BANK_LEN (SABER_K * SABER_K * ONE_VECTOR)

static void GenMatrix(polyvec *a, const unsigned char *seed, unsigned char* buf) {
  uint16_t temp_ar[SABER_N];
  int i,j,k;
  uint16_t mod = (SABER_Q-1);

  shake128(buf, BYTE_BANK_LEN,seed,SABER_SEEDBYTES);
  
  for(i=0;i<SABER_K;i++)
  {
    for(j=0;j<SABER_K;j++)
    {
	BS2POL(buf+(i*SABER_K+j)*ONE_VECTOR,temp_ar);
	for(k=0;k<SABER_N;k++){
		a[i].vec[j].coeffs[k] = (temp_ar[k])& mod ;
	}
    }
  }
}

void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk,
                        unsigned char seed[SABER_SEEDBYTES],
                        unsigned char noiseseed[SABER_COINBYTES],
                        struct eph_buffer* const ebuf) {
  polyvec* const a = ebuf->a;
  uint16_t (* const skpv) [SABER_N] = ebuf->skpv;
  uint16_t (* const res) [SABER_N] = ebuf->res;
 
  int32_t i,j;
  uint16_t mod_q=SABER_Q-1;

  GenMatrix(a, seed, ebuf->genmat_buf);	//sample matrix A

  GenSecret(skpv,noiseseed);//generate secret from constant-time binomial distribution

  //------------------------do the matrix vector multiplication and rounding------------
        
        memset(res, 0x0, sizeof(uint16_t)*SABER_N*SABER_K);
	MatrixVectorMul(a,skpv,res,SABER_Q-1,1,
                        ebuf->pol_mul_tmp, ebuf->tc_tmp);
	
	//-----now rounding
	for(i=0;i<SABER_K;i++){ //shift right EQ-EP bits
		for(j=0;j<SABER_N;j++){
			res[i][j]=(res[i][j] + h1) & (mod_q);
			res[i][j]=(res[i][j]>>(SABER_EQ-SABER_EP));
		}
	}
	
	//------------------unload and pack sk=3 x (256 coefficients of 14 bits)-------
	POLVEC2BS(sk, skpv, SABER_Q);

	//------------------unload and pack pk=256 bits seed and 3 x (256 coefficients of 11 bits)-------

	
	POLVEC2BS(pk, res, SABER_P); // load the public-key coefficients

	for(i=0;i<SABER_SEEDBYTES;i++){ // now load the seedbytes in PK. Easy since seed bytes are kept in byte format.
		pk[SABER_POLYVECCOMPRESSEDBYTES + i]=seed[i]; 
	}
}


void indcpa_kem_enc(unsigned char *message_received,
                    unsigned char *noiseseed, const unsigned char *pk,
                    unsigned char *ciphertext, struct eph_buffer* const ebuf) { 
	uint32_t i,j,k;
	polyvec* const a = ebuf->a;
	unsigned char seed[SABER_SEEDBYTES];
        //public key of received by the client
	uint16_t (* const pkcl) [SABER_N] = ebuf->pkcl;
        uint16_t (* const skpv1) [SABER_N] = ebuf->skpv;
        uint16_t (* const res) [SABER_N] = ebuf->res;

	uint16_t * const message = ebuf->message;

	uint16_t mod_p=SABER_P-1;
	uint16_t mod_q=SABER_Q-1;
	
	uint16_t vprime[SABER_N];

	unsigned char msk_c[SABER_SCALEBYTES_KEM];
	
	for(i=0;i<SABER_SEEDBYTES;i++){ // extract the seedbytes from Public Key.
		seed[i]=pk[ SABER_POLYVECCOMPRESSEDBYTES + i]; 
	}

	GenMatrix(a, seed, ebuf->genmat_buf);				

	GenSecret(skpv1,noiseseed);//generate secret from constant-time binomial distribution

	//-----------------matrix-vector multiplication and rounding

        memset(res, 0x0, sizeof(uint16_t) * SABER_K * SABER_N);
	MatrixVectorMul(a,skpv1,res,SABER_Q-1,0, ebuf->pol_mul_tmp, ebuf->tc_tmp);
	
	//-----now rounding

	for(i=0;i<SABER_K;i++){ //shift right EQ-EP bits
		for(j=0;j<SABER_N;j++){
			res[i][j]=( res[i][j]+ h1 ) & mod_q;
			res[i][j]=(res[i][j]>> (SABER_EQ-SABER_EP) );
		}
	}

	POLVEC2BS(ciphertext, res, SABER_P);

	//------now calculate the v'

	//-------unpack the public_key
        //
        //
	//pkcl is the b in the protocol
	BS2POLVEC(pk,pkcl,SABER_P);

        memset(vprime, 0x0, sizeof(uint16_t) * SABER_N);

	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			skpv1[i][j]=skpv1[i][j] & (mod_p);
		}
	}

	// vector-vector scalar multiplication with mod p
	InnerProd(pkcl,skpv1,mod_p,vprime, ebuf->pol_mul_tmp, ebuf->tc_tmp);

	//addition of h1 to vprime
	for(i=0;i<SABER_N;i++)
	    vprime[i]=vprime[i]+h1;

	// unpack message_received;
	for(j=0; j<SABER_KEYBYTES; j++)
	{
		for(i=0; i<8; i++)
		{
			message[8*j+i] = ((message_received[j]>>i) & 0x01);
		}
	}

	// message encoding
	for(i=0; i<SABER_N; i++) {
            message[i] = (message[i]<<(SABER_EP-1));		
	}

	for(k=0;k<SABER_N;k++) {
	    vprime[k]=( (vprime[k] - message[k]) & (mod_p) )>>(SABER_EP-SABER_ET);
	}

	#if Saber_type == 1
		SABER_pack_3bit(msk_c, vprime);
	#elif Saber_type == 2
		SABER_pack_3bit(msk_c, vprime);
	#elif Saber_type == 3
		SABER_pack_6bit(msk_c, vprime);
	#endif

	for(j=0;j<SABER_SCALEBYTES_KEM;j++){
		ciphertext[SABER_POLYVECCOMPRESSEDBYTES + j] = msk_c[j];
	}
}


void indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext,
                    unsigned char message_dec[], struct eph_buffer* const ebuf) {
	uint32_t i,j;
	uint16_t (* const sksv) [SABER_N] = ebuf->skpv; // sk of the server
	uint16_t (* const pksv) [SABER_N] = ebuf->pkcl;
	uint8_t scale_ar[SABER_SCALEBYTES_KEM];
	uint16_t mod_p=SABER_P-1;
	uint16_t v[SABER_N];
	uint16_t op[SABER_N];

	BS2POLVEC(sk, sksv, SABER_Q); //sksv is the secret-key
	BS2POLVEC(ciphertext, pksv, SABER_P); //pksv is the ciphertext

	// vector-vector scalar multiplication with mod p
        memset(v, 0x0, sizeof(uint16_t)*SABER_N);

	for(i=0;i<SABER_K;i++){
		for(j=0;j<SABER_N;j++){
			sksv[i][j]=sksv[i][j] & (mod_p);
		}
	}

	InnerProd(pksv,sksv,mod_p,v, ebuf->pol_mul_tmp, ebuf->tc_tmp);

	//Extraction
	for(i=0;i<SABER_SCALEBYTES_KEM;i++){
		scale_ar[i]=ciphertext[SABER_POLYVECCOMPRESSEDBYTES+i];
	}

	#if Saber_type == 1
		SABER_un_pack3bit(scale_ar, op);
	#elif Saber_type == 2
		SABER_un_pack3bit(scale_ar, op);
	#elif Saber_type == 3
		SABER_un_pack6bit(scale_ar, op);
	#endif

	//addition of h1
	for(i=0;i<SABER_N;i++){
		v[i]= ( ( v[i] + h2 - (op[i]<<(SABER_EP-SABER_ET)) ) & (mod_p) ) >> (SABER_EP-1);
	}

	// pack decrypted message
	POL2MSG(v, message_dec);
}

void MatrixVectorMul(polyvec *a, uint16_t skpv[SABER_K][SABER_N],
                     uint16_t res[SABER_K][SABER_N], uint16_t mod,
                     int16_t transpose, uint16_t buf[512],
                     uint16_t* const tc_buf) {

    uint16_t acc[SABER_N]; 
    int32_t i,j,k;

    // TODO: remove this useless branch
    if(transpose==1){
        for(i=0;i<SABER_K;i++){
	    for(j=0;j<SABER_K;j++){
		pol_mul((uint16_t *)&a[j].vec[i], skpv[j], acc, SABER_Q,
                        SABER_N, buf, tc_buf);			

		for(k=0;k<SABER_N;k++){
		    res[i][k]=res[i][k]+acc[k];
		    res[i][k]=(res[i][k]&mod); //reduction mod p
		    acc[k]=0; //clear the accumulator
		}
	    }
	}
    }

    else{
        for(i=0;i<SABER_K;i++){
            for(j=0;j<SABER_K;j++){
                pol_mul((uint16_t *)&a[i].vec[j], skpv[j], acc, SABER_Q,
                        SABER_N, buf, tc_buf);			
                for(k=0;k<SABER_N;k++){
                    res[i][k]=res[i][k]+acc[k];
                    res[i][k]=res[i][k]&mod; //reduction
                    acc[k]=0; //clear the accumulator
                }
            }
        }
    }
}

void POL2MSG(uint16_t *message_dec_unpacked, unsigned char *message_dec){
    int32_t i,j;
    for(j=0; j<SABER_KEYBYTES; j++) {
        message_dec[j] = 0;
	for(i=0; i<8; i++) {
            message_dec[j] = message_dec[j] | (message_dec_unpacked[j*8 + i] <<i);
        }
    }
}

void InnerProd(uint16_t pkcl[SABER_K][SABER_N],uint16_t skpv[SABER_K][SABER_N],
               uint16_t mod,uint16_t res[SABER_N], uint16_t buf[512],
               uint16_t* const tc_buf){
    uint32_t j,k;
    uint16_t acc[SABER_N]; 

    // vector-vector scalar multiplication with mod p
    for(j=0;j<SABER_K;j++){
        pol_mul(pkcl[j], skpv[j], acc , SABER_P, SABER_N, buf, tc_buf);
        for(k=0;k<SABER_N;k++){
            res[k]=res[k]+acc[k];
            res[k]=res[k]&mod; //reduction
            acc[k]=0; //clear the accumulator
        }
    }
}
