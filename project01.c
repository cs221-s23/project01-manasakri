#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "passwords.h"
#include "sha256.h"

#define DIG_BIN_LEN 32
#define DIG_STR_LEN ((DIG_BIN_LEN * 2) + 1)

void sha256(char *dest, char *src) {
    // zero out the sha256 context
    struct sha256_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    // zero out the binary version of the hash digest
    unsigned char dig_bin[DIG_BIN_LEN];
    memset(dig_bin, 0, DIG_BIN_LEN);

    // zero out the string version of the hash digest
    memset(dest, 0, DIG_STR_LEN);

    // compute the binary hash digest
    __sha256_init_ctx(&ctx);
    __sha256_process_bytes(src, strlen(src), &ctx);
    __sha256_finish_ctx(&ctx, dig_bin);

    // convert it into a string of hexadecimal digits
    for (int i = 0; i < DIG_BIN_LEN; i++) {
        snprintf(dest, 3, "%02x", dig_bin[i]);
        dest += 2;
    }
}

char* change_leet(char* input_string); //function to change characters to leet 
char* change_leet(char* input_string) {
	char* changed_string =  malloc(strlen(input_string));
    for (int i = 0 ; i < strlen(input_string); i++ ) {
        char c = input_string[i]; //'c' is the password from list of passwords 
        if (c == 'a'){
        	changed_string[i] = '@';
        }
        else if (c == 's') {
            changed_string[i] = '$' ;
        }
        else if (c == 'o') {
            changed_string[i] = '0' ;
        }
        else if (c == 't') {
            changed_string[i] = '+' ;
        }
        else if (c == 'i') {
            changed_string[i] = '!' ;
        }
        else if (c == 'h') {
            changed_string[i] = '#' ;
        }
        else if (c == 'e') {
            changed_string[i] = '3' ;
        }
        else {
        	changed_string[i] = c; // if leet chars don't match, then print normal letter
        }
    }
    return changed_string; //returns string with new leet chars
}

char* change_plus_one(char* input_string); //function that concats 1 to end of password string 
char* change_plus_one(char* input_string) {
    size_t len = strlen(input_string);
    char* changed_string = malloc(len + 1 + 1);
    strcpy(changed_string, input_string);

    changed_string[len] = '1';
    changed_string[len + 1] = '\0';
    return changed_string ; 
}

int main(int argc, char *argv[]) {
	char* input_hash = argv[1];
	char hashed_striing[DIG_STR_LEN];
	char* string_leet;
	char* plus_one;
	char* temp_string;

 	for ( int i=0 ; i < 10000 ; i++ ) { //compares input hash to password and returns password 
 		temp_string = passwords[i];
 		sha256(hashed_striing, temp_string);
 		if (strcmp(hashed_striing, input_hash) == 0 ) {
 		printf("%s\n", temp_string) ;
 		exit(0); 
        } 
        
        else {
        	string_leet = change_leet(temp_string); //if input hash is not found in list of passwords, check for leet chars and return password with leets
        	sha256(hashed_striing, string_leet);
        	if (strcmp(hashed_striing, input_hash) == 0) {
        		printf("%s\n", string_leet);
                exit(0);
            }
          	else {
          		plus_one = change_plus_one(temp_string); //checks for input hash with 1 added to the end of password, 
                sha256(hashed_striing, plus_one);
                if (strcmp(hashed_striing, input_hash) == 0) {
                	printf("%s\n", plus_one);
                    exit(0);
                 }
             }
          }
      }
      printf("not found\n"); //if all else fails 
}
