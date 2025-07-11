#include "poly_mul.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#define SCHB_N 16

#define N_RES (SABER_N << 1)
#define N_SB (SABER_N >> 2)
#define N_SB_RES (2*N_SB-1)

void pol_mul(uint16_t* a, uint16_t* b, uint16_t* res, uint16_t p, uint32_t n,
             uint16_t c[512], uint16_t* const tc_buf) { 
	// Polynomial multiplication using the schoolbook method, c[x] = a[x]*b[x] 
	// SECURITY NOTE: TO BE USED FOR TESTING ONLY.  
	uint32_t i;

//-------------------normal multiplication-----------------

        memset(c, 0x0, sizeof(uint16_t) * 512);

	toom_cook_4way(a, b, c, tc_buf);

	//---------------reduction-------
	for(i=n;i<2*n;i++){
		res[i-n]=(c[i-n]-c[i])&(p-1);
	}
}

static void karatsuba_simple(const uint16_t* a_1,const uint16_t* b_1, uint16_t* result_final){//uses 10 registers

	uint16_t N=64;
	uint16_t d01[N/2-1];
	uint16_t d0123[N/2-1];
	uint16_t d23[N/2-1];
	uint16_t result_d01[N-1];	

	int32_t i,j;

	memset(result_d01,0,(N-1)*sizeof(uint16_t));
	memset(d01,0,(N/2-1)*sizeof(uint16_t));
	memset(d0123,0,(N/2-1)*sizeof(uint16_t));
	memset(d23,0,(N/2-1)*sizeof(uint16_t));
	memset(result_final,0,(2*N-1)*sizeof(uint16_t));

	uint16_t acc1,acc2,acc3,acc4,acc5,acc6,acc7,acc8,acc9,acc10;


	for (i = 0; i < N/4; i++) {
		acc1=a_1[i];//a0
		acc2=a_1[i+N/4];//a1
		acc3=a_1[i+2*N/4];//a2
		acc4=a_1[i+3*N/4];//a3	
		for (j = 0; j < N/4; j++) {

			acc5=b_1[j];//b0
			acc6=b_1[j+N/4];//b1

			result_final[i+j+0*N/4]=result_final[i+j+0*N/4]+acc1*acc5;
			result_final[i+j+2*N/4]=result_final[i+j+2*N/4]+acc2*acc6;

			acc7=acc5+acc6;//b01
			acc8=acc1+acc2;//a01
			d01[i+j]=d01[i+j] + acc7*acc8;
	//--------------------------------------------------------

			acc7=b_1[j+2*N/4];//b2
			acc8=b_1[j+3*N/4];//b3			
			result_final[i+j+4*N/4]=result_final[i+j+4*N/4]+acc7*acc3;

			result_final[i+j+6*N/4]=result_final[i+j+6*N/4]+acc8*acc4;

			acc9=acc3+acc4;
			acc10=acc7+acc8;
			d23[i+j]=d23[i+j] + acc9*acc10;
	//--------------------------------------------------------

			acc5=acc5+acc7;//b02
			acc7=acc1+acc3;//a02
			result_d01[i+j+0*N/4]=result_d01[i+j+0*N/4]+acc5*acc7;

			acc6=acc6+acc8;//b13
			acc8=acc2+acc4;			
			result_d01[i+j+ 2*N/4]=result_d01[i+j+ 2*N/4]+acc6*acc8;

			acc5=acc5+acc6;
			acc7=acc7+acc8;
			d0123[i+j]=d0123[i+j] + acc5*acc7;
		}
	}

//------------------2nd last stage-------------------------

	for(i=0;i<N/2-1;i++){
		d0123[i]=d0123[i]-result_d01[i+0*N/4]-result_d01[i+2*N/4];
		d01[i]=d01[i]-result_final[i+0*N/4]-result_final[i+2*N/4];
		d23[i]=d23[i]-result_final[i+4*N/4]-result_final[i+6*N/4];
	}

	for(i=0;i<N/2-1;i++){
		result_d01[i+1*N/4]=result_d01[i+1*N/4]+d0123[i];
		result_final[i+1*N/4]=result_final[i+1*N/4]+d01[i];
		result_final[i+5*N/4]=result_final[i+5*N/4]+d23[i];
	}

//------------Last stage---------------------------
	for(i=0;i<N-1;i++){
		result_d01[i]=result_d01[i]-result_final[i]-result_final[i+N];
	}
	
	for(i=0;i<N-1;i++){
		result_final[i+1*N/2]=result_final[i+1*N/2]+result_d01[i];//-result_d0[i]-result_d1[i];		
	}

}

void toom_cook_4way (const uint16_t* a1,const uint16_t* b1, uint16_t* result,
                     uint16_t * const tc_buf) {
	uint16_t inv3 = 43691, inv9 = 36409, inv15 = 61167;

	uint16_t* const aw1 = tc_buf;
        uint16_t* const aw2 = aw1 + N_SB;
        uint16_t* const aw3 = aw2 + N_SB;
        uint16_t* const aw4 = aw3 + N_SB;
        uint16_t* const aw5 = aw4 + N_SB;
        uint16_t* const aw6 = aw5 + N_SB;
        uint16_t* const aw7 = aw6 + N_SB;
	uint16_t* const bw1 = aw7 + N_SB;
        uint16_t* const bw2 = bw1 + N_SB;
        uint16_t* const bw3 = bw2 + N_SB;
        uint16_t* const bw4 = bw3 + N_SB;
        uint16_t* const bw5 = bw4 + N_SB;
        uint16_t* const bw6 = bw5 + N_SB;
        uint16_t* const bw7 = bw6 + N_SB;

	uint16_t* const w1 = bw7 + N_SB;
        uint16_t* const w2 = w1 + N_SB_RES;
        uint16_t* const w3 = w2 + N_SB_RES;
        uint16_t* const w4 = w3 + N_SB_RES;
        uint16_t* const w5 = w4 + N_SB_RES;
	uint16_t* const w6 = w5 + N_SB_RES;
        uint16_t* const w7 = w6 + N_SB_RES;

	uint16_t r0, r1, r2, r3, r4, r5, r6, r7;
	uint16_t *A0, *A1, *A2, *A3, *B0, *B1, *B2, *B3;
	A0 = (uint16_t*)a1;
	A1 = (uint16_t*)&a1[N_SB];
	A2 = (uint16_t*)&a1[2*N_SB];
	A3 = (uint16_t*)&a1[3*N_SB];
	B0 = (uint16_t*)b1;
	B1 = (uint16_t*)&b1[N_SB];
	B2 = (uint16_t*)&b1[2*N_SB];
	B3 = (uint16_t*)&b1[3*N_SB];

	uint16_t * C;
	C = result;

	int i,j;

        memset(w1, 0x0, sizeof(uint16_t) * N_SB_RES * 7);

// EVALUATION
	for (j = 0; j < N_SB; ++j) {
		r0 = A0[j];
		r1 = A1[j];
		r2 = A2[j];
		r3 = A3[j];
		r4 = r0 + r2;
		r5 = r1 + r3;
		r6 = r4 + r5; r7 = r4 - r5;
		aw3[j] = r6;
		aw4[j] = r7;
		r4 = ((r0 << 2)+r2) << 1;
		r5 = (r1 << 2) + r3;
		r6 = r4 + r5; r7 = r4 - r5;
		aw5[j] = r6;
		aw6[j] = r7;
		r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
		aw2[j] = r4; aw7[j] = r0;
		aw1[j] = r3;
	}
	for (j = 0; j < N_SB; ++j) {
		r0 = B0[j];
		r1 = B1[j];
		r2 = B2[j];
		r3 = B3[j];
		r4 = r0 + r2;
		r5 = r1 + r3;
		r6 = r4 + r5; r7 = r4 - r5;
		bw3[j] = r6;
		bw4[j] = r7;
		r4 = ((r0 << 2)+r2) << 1;
		r5 = (r1 << 2) + r3;
		r6 = r4 + r5; r7 = r4 - r5;
		bw5[j] = r6;
		bw6[j] = r7;
		r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
		bw2[j] = r4; bw7[j] = r0;
		bw1[j] = r3;
	}

// MULTIPLICATION

	karatsuba_simple(aw1, bw1, w1);
	karatsuba_simple(aw2, bw2, w2);
	karatsuba_simple(aw3, bw3, w3);
	karatsuba_simple(aw4, bw4, w4);
	karatsuba_simple(aw5, bw5, w5);
	karatsuba_simple(aw6, bw6, w6);
	karatsuba_simple(aw7, bw7, w7);

// INTERPOLATION
	for (i = 0; i < N_SB_RES; ++i) {
		r0 = w1[i];
		r1 = w2[i];
		r2 = w3[i];
		r3 = w4[i];
		r4 = w5[i];
		r5 = w6[i];
		r6 = w7[i];

		r1 = r1 + r4;
		r5 = r5 - r4;
		r3 = ((r3-r2) >> 1);
		r4 = r4 - r0;
		r4 = r4 - (r6 << 6);
		r4 = (r4 << 1) + r5;
		r2 = r2 + r3;
		r1 = r1 - (r2 << 6) - r2;
		r2 = r2 - r6;
		r2 = r2 - r0;
		r1 = r1 + 45*r2;
		r4 = (((r4 - (r2 << 3))*inv3) >> 3);
		r5 = r5 + r1;
		r1 = (((r1 + (r3 << 4))*inv9) >> 1);
		r3 = -(r3 + r1);
		r5 = (((30*r1 - r5)*inv15) >> 2);
		r2 = r2 - r4;
		r1 = r1 - r5;

		C[i]     += r6;
		C[i+64]  += r5;
		C[i+128] += r4;
		C[i+192] += r3;
		C[i+256] += r2;
		C[i+320] += r1;
		C[i+384] += r0;
	}
}
