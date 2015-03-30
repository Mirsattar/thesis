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

using namespace std;

class encryption
{
public: 
    void gen(char generStr[], int lenght,  int l)
    {
        memcpy(param, generStr, length);
        pairing_init_set_buf(pairing, param, lenght);
        element_from_hash(H, (void*)"ABCDEF", 6);
        element_init_G1(P, pairing);
        element_init_Zr(a, pairing);
        element_init_G1(secret_key[0], pairing);
        element_random(P);
        element_random(a);
        element_pow_zn(Q, P, a);
        element_pow_zn(secret_key[0], H, a);
    }
    
    void der(char* name1, int length1, char* name2, int length2, element_t& Sw)
    {
        element_t pw0, pw1, Hw0, Hw1;
        element_init_Zr(pw0, pairing);
        element_init_Zr(pw1, pairing);
        element_random(pw0);
        element_random(pw1);
        
        element_t Rw0, Rw1;
        element_init_Zr(Rw0, pairing);
        element_init_Zr(Rw1, pairing);
        element_pow_zn(Rw0, P, pw0);
        element_pow_zn(Rw1, P, pw1);
        
        element_t Sw0, Sw1;
        element_init_Zr(Sw0, pairing);
        element_init_Zr(Sw1, pairing);
        
        element_from_hash(Hw0, name1, length1);
        element_from_hash(Hw1, name2, length2);
        
        element_t tmp0, tmp1;
        element_pow_zn(tmp0, Hw0, pw0);
        element_pow_zn(tmp1, Hw1, pw1);
        
        element_add(Sw0, Sw, tmp0);
        element_add(Sw1, Sw, tmp1);
           
    }
    
    void Enc(long M, int length, std::vector<long>& w)
    {
        element_t y;
        element_init_Zr(y, pairing);
        element_random(y);
        
        element_t tmp_w;
        element_t tmp;
        
        
        element_pow_zn(tmp, P, y);
        element_t* cipher_text = new element_t[w.size()+2];
        element_set(cipher_text[0], tmp);
        
        int i;
        for(i =1; i<(w.size()+1); ++i)
        {
            element_from_hash(tmp_w, &w[i-1], 1);
            element_pow_zn(tmp, tmp_w, y);
            element_set(cipher_text[0], tmp);
        }
        
        element_t d;
        element_init_Zr(d, pairing);
        pairing_pp_t pp;
        pairing_pp_init(pp, Q, pairing); 
        pairing_pp_apply(d, H, pp); 
        
        element_set_si(tmp, M); 
        element_mul(tmp, tmp, d);
        element_set(cipher_text[i], tmp);
        
        
        
        pairing_pp_clear(pp);
        
    }
    
    
    void dec(element_t* sk, int cipherKey, std::vector<long>& w, element_t* cipher_text, int cipherLength)
    {
        element_t d;
        element_t M;
        element_t numerator;
        element_t denumerator;
        element_init_Zr(numerator, pairing);
        element_init_Zr(d, pairing);
        element_init_Zr(denumerator, pairing);
        element_init_Zr(M, pairing);
        element_t tmp;
        pairing_pp_t pp;
        pairing_pp_init(pp, cipher_text[0], pairing); 
        pairing_pp_apply(numerator, sk[cipherKey-1], pp);
        
        for(int i=1; i<cipherLength-1; ++i)
        {
            pairing_pp_init(pp, cipher_text[i], pairing); 
            pairing_pp_apply(tmp, sk[i-1], pp);
            element_mul(denumerator, denumerator, tmp);
        }
        
        element_div(d, numerator, denumerator);
        element_div(M, cipher_text[cipherLength-1], d);
    }
private:
    pairing_t pairing;
    char param[1024];
    int length;
    element_t P, Q, a, H;
    std::vector<element_t> secret_key;
};


int main(int argc, char** argv) {

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    
    
    
  
    
    return 0;
}
