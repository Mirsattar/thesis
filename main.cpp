/* 
 * File:   main.cpp
 * Author: sattar
 *
 * Created on March 25, 2015, 5:01 PM
 */

#include <cstdlib>

#include <pbc.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <ctime>
#include <fstream>

using namespace std;

class encryption
{
public: 
    encryption(char* fileName)
    {
        fstream fs;
        fs.open(fileName, std::fstream::in| std::fstream::binary);
        size_t count = 1024;
        fs.read(param, count);
        
        pairing_init_set_buf(pairing, param, count);        
        fs.close();
    }
    
    void set_elemG2(element_t& elem)
    {
        element_init_G2(elem, pairing);
    }
    void gen(int l)
    {
        element_init_G2(H, pairing);
        element_from_hash(H, (void*)"ABCDEF", 6);
        element_init_G1(P, pairing);
        element_init_G1(Q, pairing);
        element_init_Zr(a, pairing);
       
        secret_key = new element_t[1];
        element_init_G2(secret_key[0], pairing);
        element_random(P);
        element_random(a);
        element_pow_zn(Q, P, a);
        
        element_t tmp;
        element_init_G2(tmp, pairing);
        element_mul(secret_key[0], H, a);
        cipherKeyLength = 1;
    }
    
    void der(string name1, int length1, string name2, int length2, element_t*& Sw0, element_t*& Sw1)
    {
        element_t pw0, pw1, Hw0, Hw1;
        element_init_Zr(pw0, pairing);
        element_init_Zr(pw1, pairing);
        element_random(pw0);
        element_random(pw1);

        element_init_G2(Sw0[0], pairing);
        element_init_G2(Sw1[0], pairing);
        element_mul(Sw0[0], P, pw0);
        element_mul(Sw1[0], P, pw1);
        
        element_init_G2(Sw0[1], pairing);
        element_init_G2(Sw1[1], pairing);
        
        element_init_G2(Hw0, pairing);
        element_init_G2(Hw1, pairing);
        
        element_from_hash(Hw0, const_cast<char*>(name1.c_str()), length1);
        element_from_hash(Hw1, const_cast<char*>(name2.c_str()), length2);
        
        element_t tmp0, tmp1;
        element_init_G2(tmp0, pairing);
        element_init_G2(tmp1, pairing);
        element_mul(tmp0, Hw0, pw0);
        element_mul(tmp1, Hw1, pw1);
               
        element_add(Sw0[1], secret_key[0], tmp0);
        element_add(Sw1[1], secret_key[0], tmp1);
        
        
        //element_printf("cipher text 1 :%B \n", Sw0);
        //element_printf("cipher text 2 :%B \n", Sw1);
    }
    
    void Enc(std::vector<string>& w, element_t*& cipher_text)
    {
        element_t y;
        element_init_Zr(y, pairing);
        element_random(y);

        element_t tmp_w;
        element_t tmp_w2;
        element_t tmp;
        element_init_G2(tmp_w, pairing);
        element_init_G2(tmp_w2, pairing);
        element_init_G1(tmp, pairing);
                
        element_mul(tmp, P, y);
        
        cipher_text = new element_t[w.size()+2];
        element_init_G1(cipher_text[0], pairing);
        element_set(cipher_text[0], tmp);
        int i;
        for(i =1; i<(w.size()+1); ++i)
        {
            element_init_G2(cipher_text[i], pairing);
            element_from_hash(tmp_w, &w[i-1], 1);
            element_mul(tmp_w2, tmp_w, y);
            element_set(cipher_text[i], tmp_w2);
        }
        element_init_G2(cipher_text[i], pairing);
        element_t d;
        element_init_GT(d, pairing);
        pairing_apply(d, Q, H, pairing); 
       
        element_init_G2(symmetricKey, pairing);
        element_random(symmetricKey);
        
        element_printf("We are going to encrypt a symmetric key for user %s : %B \n", w[0].c_str(), symmetricKey);
        
        
        element_mul(tmp_w, d, symmetricKey);
        element_set(cipher_text[i], tmp_w);

    }
    
    
    void dec(std::vector<string>& w, element_t*& cipher_text, element_t*& secret_key)
    {
        int cipherLength = w.size()+2;
        element_t d;
        element_t M;
        element_t numerator;
        element_t denumerator;
        element_init_GT(numerator, pairing);
        element_init_GT(d, pairing);
        element_init_GT(denumerator, pairing);
        mpz_t one;
        mpz_init (one);
        element_set_mpz(denumerator, one);
        element_init_same_as(denumerator, d);
        
        element_init_G2(M, pairing);
        element_t tmp;
        element_init_GT(tmp, pairing);
        
        pairing_apply(numerator, Q, H, pairing);

        for(int i=1; i<cipherLength-1; ++i)
        {
            pairing_apply(tmp, secret_key[i-1], cipher_text[i], pairing);
            element_mul(denumerator, denumerator, tmp);
        }
 

        element_div(d, numerator, denumerator);
        
        element_div(M, cipher_text[cipherLength-1], numerator);

        element_printf("Decrypted symmetric key for user %s : %B \n", w[0].c_str(), M);
        

    }
    
    element_t symmetricKey;
    
    pairing_t pairing;
    char param[1024];
    int length;
    element_t P, Q, a, H;
    element_t* secret_key;
    int cipherKeyLength;
};




int main(int argc, char** argv) {
    
    encryption* e = new encryption(argv[1]);
    std::vector<string> names;
    
    pairing_t pairing;
    
    names.push_back("lol1");
    names.push_back("lol2");
  

    element_t* cipher;

    element_t* Sw0 = new element_t[2];
    element_t* Sw1 = new element_t[2];
    
    e->gen(1);
    e->der(names[0], 4, names[1], 4, Sw0, Sw1);
    
    std::vector<string> name1;
    name1.push_back(names[0]);
    
    std::vector<string> name2;
    name2.push_back(names[1]);
    
    e->Enc(name1, cipher);
    e->dec(name1, cipher, Sw0);
    
    e->Enc(name2, cipher);
    e->dec(name2, cipher, Sw1);
    
    delete e;
    return 0;
}

