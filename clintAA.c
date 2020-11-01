#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>
/* codul de eroare returnat de anumite apeluri */
extern int errno;

/* portul de conectare la server*/
int port;
unsigned char *K3 = (unsigned char *)"00112233445566778899AABBCCDDEEFF"; //cheia pe care o are nodul B
void handleErrors(void);
int decriptare_chei(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                    unsigned char *plaintext);
int cripteaza_cheia(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                    unsigned char *plaintext);
unsigned char **impartire_blocuri(unsigned char *mesaj, int nr_blocuri);
void **impartire_blocuri_decriptare(unsigned char *mesaj, int nr_blocuri, unsigned char **blocuri); // o folosesc la decriptare; blocurile sunt fara padding
unsigned char *xor_function(unsigned char *plaintext, unsigned char *initialization_vector);
int cripteaza_cheia_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
int cripteaza_cheia_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cfb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
void cbc1(unsigned char **blocuri, int nr_blocuri, unsigned char *key, unsigned char *iv, unsigned char *cbc_final);
void implementare_cbc(unsigned char *xored, unsigned char *key, unsigned char *cbc_chiper);
void implementare_cfb(unsigned char * iv,unsigned char * key, unsigned char * paintext, unsigned char * cipher_text);
int main(int argc, char *argv[])
{
    int sd;                    // descriptorul de socket
    struct sockaddr_in server; // structura folosita pentru conectare
                               // mesajul trimis
    int nr = 0;
    char buf[10];
    //impartire_blocuri("eufwgqoufhwifpiqwfhpiqwhwfpiqhwpifhqhqpif");
    /* exista toate argumentele in linia de comanda? */
    if (argc != 3)
    {
        printf("Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }

    /* stabilim portul */
    port = atoi(argv[2]);

    /* cream socketul */
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Eroare la socket().\n");
        return errno;
    }

    /* umplem structura folosita pentru realizarea conexiunii cu serverul */
    /* familia socket-ului */
    server.sin_family = AF_INET;
    /* adresa IP a serverului */
    server.sin_addr.s_addr = inet_addr(argv[1]);
    /* portul de conectare */
    server.sin_port = htons(port);

    /* ne conectam la server */
    if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("[client]Eroare la connect().\n");
        return errno;
    }
    char msg[200];
    if (read(sd, msg, sizeof(msg)) < 0)
    {
        perror("[client]Eroare la read() de la server.\n");
        return errno;
    }
    /* afisam mesajul primit */
    printf("[client]Mesajul primit este: %s\n", msg);

    printf("[client]Introduceti optiunea de criptare:");
    fflush(stdout);
    //read(0, buf, sizeof(buf));
    nr = atoi(buf);
    scanf("%d", &nr);

    if (write(sd, &nr, sizeof(int)) < 0)
    {
        perror("[client]Eroare la write() spre server.\n");
        return errno;
    }
    if (nr == 0)
    {
        //primeste lungimea cheii
        int lungime_cheie1, lungime_vi;
        unsigned char cheie_criptata[128], vi_criptat[128];
        if (read(sd, &lungime_cheie1, sizeof(int)) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //primeste cheia criptata
        if (read(sd, cheie_criptata, lungime_cheie1) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //printf("Am primit cheia");
        //primeste VI
        if (read(sd, &lungime_vi, sizeof(int)) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //primeste cheia criptata
        if (read(sd, vi_criptat, lungime_vi) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //apelam functia de decriptare
        int lungime_cheie_decriptare, lungime_vi_decriptare;
        unsigned char cheie_decriptata[17], vi_decriptat[17];
        //print_binary(cheie_criptata);
        lungime_cheie_decriptare = decriptare_chei(cheie_criptata, lungime_cheie1, K3, cheie_decriptata);
        lungime_vi_decriptare = decriptare_chei(vi_criptat, lungime_vi, K3, vi_decriptat);
        printf("%s\n%s\n", cheie_decriptata, vi_decriptat);
        //trebuie sa transmitem mesajul de confirmare
        unsigned char *msg_confirmare = (unsigned char *)"1";
        int lungime_mes = strlen(msg_confirmare);
        unsigned char to_send_confirm[16];
        int len_to_send;
        len_to_send = cripteaza_cheia_cbc(msg_confirmare, lungime_mes, cheie_decriptata, vi_decriptat, to_send_confirm);
        printf("%s\n", to_send_confirm);
        //transmitem mesajul de confirmare criptat
        //mai intai lungimea sa
        if (write(sd, &len_to_send, sizeof(int)) < 0)
        {
            perror("[client]Eroare la write() spre server.\n");
            return errno;
        }
        if (write(sd, to_send_confirm, len_to_send) < 0)
        {
            perror("[client]Eroare la write() spre server.\n");
            return errno;
        }
    }
    else
    {
        //primeste lungimea cheii
        int lungime_cheie2, lungime_vi;
        unsigned char cheie_criptata[16], vi_criptat[16];
        if (read(sd, &lungime_cheie2, sizeof(int)) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        printf("%d\n", lungime_cheie2);
        //primeste cheia criptata
        if (read(sd, cheie_criptata, lungime_cheie2) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //printf("Am primit cheia");
        //primeste VI
        if (read(sd, &lungime_vi, sizeof(int)) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //primeste cheia criptata
        if (read(sd, vi_criptat, lungime_vi) < 0)
        {
            perror("[client]Eroare la read() de la server.\n");
            return errno;
        }
        //apelam functia de decriptare
        int lungime_cheie_decriptare, lungime_vi_decriptare;
        unsigned char cheie_decriptata[16], vi_decriptat[16];
        lungime_cheie_decriptare = decriptare_chei(cheie_criptata, lungime_cheie2, K3, cheie_decriptata);
        //cheie_decriptata[lungime_cheie_decriptare] = '\0';
        lungime_vi_decriptare = decriptare_chei(vi_criptat, lungime_vi, K3, vi_decriptat);
        vi_decriptat[lungime_vi_decriptare] = '\0';
        printf("%s\n%s\n", cheie_decriptata, vi_decriptat);

        unsigned char *msg_confirmare = (unsigned char *)"1";
        int lungime_mes = strlen(msg_confirmare);
        unsigned char to_send_confirm[16];
        int len_to_send;
        len_to_send = cripteaza_cheia_cfb(msg_confirmare, lungime_mes, cheie_decriptata, vi_decriptat, to_send_confirm);
        printf("%s\n", to_send_confirm);
        //transmitem mesajul de confirmare criptat
        //mai intai lungimea sa
        if (write(sd, &len_to_send, sizeof(int)) < 0)
        {
            perror("[client]Eroare la write() spre server.\n");
            return errno;
        }
        if (write(sd, to_send_confirm, len_to_send) < 0)
        {
            perror("[client]Eroare la write() spre server.\n");
            return errno;
        }
    }
    /* inchidem conexiunea, am terminat */
    close(sd);
}
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decriptare_chei(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    //print_binary(ciphertext);

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    //print_binary(plaintext);
    return plaintext_len;
}

int cripteaza_cheia(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
//functie pentru impartire in blocuri
unsigned char **impartire_blocuri(unsigned char *mesaj, int nr_blocuri)
{
    unsigned char **blocuri = malloc(sizeof(char *) * nr_blocuri);
    for (int i = 0; i < nr_blocuri; i++)
    {
        blocuri[i] = (char *)malloc(16 * sizeof(char));
    }
    for (int i = 0; i < nr_blocuri; i++)
    {
        unsigned char bloc[17] = "";
        strncpy(bloc, mesaj + i * 16, 16);
        bloc[16] = '\0';
        if (i == nr_blocuri - 1)
        { //facem padare cand blocul e incomplet
            if (strlen(bloc) < 16)
            {
                int j = 16 - strlen(bloc);
                for (int p = strlen(bloc); p < 16; p++)
                {
                    bloc[p] = (unsigned char)j;
                }
                bloc[16] = '\0';
            }
            else if (strlen(bloc) == 0)
            {
                for (i = strlen(bloc); i < 16; i++)
                {
                    bloc[i] = (unsigned char)16;
                }
                bloc[16] = '\0';
            }
        }
        strcpy(blocuri[i], bloc);
        //printf("%s\n", blocuri[i]);
    }
    return blocuri;
}
void **impartire_blocuri_decriptare(unsigned char *mesaj, int nr_blocuri, unsigned char **blocuri)
{
    //unsigned char **blocuri = malloc(sizeof(char *) * nr_blocuri);
    for (int i = 0; i < nr_blocuri; i++)
    {
        blocuri[i] = (char *)malloc(16 * sizeof(char));
    }
    for (int i = 0; i < nr_blocuri; i++)
    {
        unsigned char bloc[17] = "";
        strncpy(bloc, mesaj + i * 16, 16);
        bloc[16] = '\0';
        strcpy(blocuri[i], bloc);
        //printf("%s\n", blocuri[i]);
    }
    //return blocuri;
}
//functie de criptare cfb
unsigned char *xor_function(unsigned char *plaintext, unsigned char *initialization_vector)
{

    unsigned char *xored = malloc(16 * sizeof(unsigned char));

    for (int i = 0; i < 16; i++)
    {
        xored[i] = (char)(plaintext[i] ^ initialization_vector[i]);
  
    }

    return xored;
}
int cripteaza_cheia_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();


    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int decriptare_cheia_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                          unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int cripteaza_cheia_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;


    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
int decriptare_cheia_cfb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                          unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;


    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;


    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void cbc1(unsigned char **blocuri, int nr_blocuri, unsigned char *key, unsigned char *iv, unsigned char *cbc_final)
{
  strcpy(cbc_final, "");
  for (int i = 0; i < nr_blocuri; i++)
  {
    unsigned char *xored = xor_function(blocuri[i], iv);
    iv[0] = '\0';
    unsigned char xored_cipher[16];
    int cipher_len;
    implementare_cbc(xored, key, xored_cipher);
    for (int i = 0; i < 16; i++)
    {
      iv[i] = xored_cipher[i];
    }
    strcat(cbc_final, xored_cipher);
  }
  cbc_final[nr_blocuri * 16] = '\0';
}
void implementare_cbc(unsigned char *xored, unsigned char *key, unsigned char *cbc_chiper)
{
  int cipher_length, cipher_length1;
  //unsigned char xored_chiper[16], xored_chiper1[16];
  cipher_length = cripteaza_cheia(xored, strlen(xored), key, cbc_chiper);
  cbc_chiper[cipher_length] = '\0';
  // cipher_length1= decriptare_chei(xored_chiper, cipher_length, key, xored_chiper1);
  // xored_chiper1[cipher_length1] = '\0';
  // printf("%s\n",xored_chiper1, cipher_length1);
  //return xored_chiper;
}
void implementare_cfb(unsigned char * iv,unsigned char * key, unsigned char * paintext, unsigned char * cipher_text){
  int len ; 
  unsigned char * encrypted;
  len = cripteaza_cheia(iv, strlen(iv), key, encrypted);
  cipher_text = xor_function(encrypted, paintext);
}