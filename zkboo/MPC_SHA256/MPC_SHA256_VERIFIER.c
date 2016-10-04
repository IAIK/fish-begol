/*
 ============================================================================
 Name        : MPC_SHA256_VERIFIER.c
 Author      : Sobuno
 Version     : 0.1
 Description : Verifies a proof for SHA-256 generated by MPC_SHA256.c
 ============================================================================
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "shared.h"

int NUM_ROUNDS = 219;

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}

}



int main(void) {
	setbuf(stdout, NULL);
	init_EVP();
	openmp_thread_setup();
	
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	clock_t begin = clock(), delta, deltaFiles;
	
	a as[NUM_ROUNDS];
	z zs[NUM_ROUNDS];
	FILE *file;

	char outputFile[10];
	sprintf(outputFile, "out%i.bin", NUM_ROUNDS);
	file = fopen(outputFile, "rb");
	if (!file) {
		printf("Unable to open file!");
	}
	fread(&as, sizeof(a), NUM_ROUNDS, file);
	fread(&zs, sizeof(z), NUM_ROUNDS, file);
	fclose(file);


	uint32_t y[8];
	reconstruct(as[0].yp[0],as[0].yp[1],as[0].yp[2],y);
	printf("Proof for hash: ");
	for(int i=0;i<8;i++) {
		printf("%02X", y[i]);
	}
	printf("\n");

	deltaFiles = clock() - begin;
	int inMilliFiles = deltaFiles * 1000 / CLOCKS_PER_SEC;
	printf("Loading files: %ju\n", (uintmax_t)inMilliFiles);


	clock_t beginE = clock(), deltaE;
	int es[NUM_ROUNDS];
	H3(y, as, NUM_ROUNDS, es);
	deltaE = clock() - beginE;
	int inMilliE = deltaE * 1000 / CLOCKS_PER_SEC;
	printf("Generating E: %ju\n", (uintmax_t)inMilliE);


	clock_t beginV = clock(), deltaV;
	#pragma omp parallel for
	for(int i = 0; i<NUM_ROUNDS; i++) {
		int verifyResult = verify(as[i], es[i], zs[i]);
		if (verifyResult != 0) {
			printf("Not Verified %d\n", i);
		}
	}
	deltaV = clock() - beginV;
	int inMilliV = deltaV * 1000 / CLOCKS_PER_SEC;
	printf("Verifying: %ju\n", (uintmax_t)inMilliV);
	
	
	delta = clock() - begin;
	int inMilli = delta * 1000 / CLOCKS_PER_SEC;

	printf("Total time: %ju\n", (uintmax_t)inMilli);
	



	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
