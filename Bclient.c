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
/* codul de eroare returnat de anumite apeluri */
extern int errno;

/* portul de conectare la server*/
int port;
unsigned char *K3 = (unsigned char *)"0011223344556677"; //cheia pe care o are nodul B
void handleErrors(void);
int decriptare_chei(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                    unsigned char *plaintext);
int cripteaza_cheia(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                    unsigned char *ciphertext);
int cripteaza_cheia_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
int cripteaza_cheia_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cfb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
int main(int argc, char *argv[])
{
  int sd;                    // descriptorul de socket
  struct sockaddr_in server; // structura folosita pentru conectare
                             // mesajul trimis
  int nr = 0;
  char buf[10];

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
  //mesajul initial de la server
  char msg[200], msg2[200];
  if (read(sd, msg, sizeof(msg)) < 0)
  {
    perror("[client]Eroare la read() de la server.\n");
    return errno;
  }
  /* afisam mesajul primit despre alegerea nodului A */
  printf("[client]Mesajul primit este: %s\n", msg);

  if (read(sd, msg2, sizeof(msg2)) < 0)
  {
    perror("[client]Eroare la read() de la server.\n");
    return errno;
  }
  /* afisam mesajul primit */
  printf("[client]Mesajul primit este: %s\n", msg2);

  //trimitem mesajul de confirmare
  fflush(stdout);
  //read(0, buf, sizeof(buf));
  nr = atoi(buf);
  scanf("%d", &nr);

  if (write(sd, &nr, sizeof(int)) < 0)
  {
    perror("[client]Eroare la write() spre server.\n");
    return errno;
  }
  int optiune_primita;
  if (read(sd, &optiune_primita, sizeof(int)) < 0)
  {
    perror("[client]Eroare la read() de la server.\n");
    return errno;
  }
  /* afisam mesajul primit */

  if (optiune_primita == 0)
  {
    //utilizeaza CBC
    // primeste lungimea cheii
    int lungime_cheie2, lungime_vi;
    unsigned char cheie_criptata[128], vi_criptat[128];
    if (read(sd, &lungime_cheie2, sizeof(int)) < 0)
    {
      perror("[client]Eroare la read() de la server.\n");
      return errno;
    }
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
    unsigned char cheie_decriptata[128], vi_decriptat[128];
    lungime_cheie_decriptare = decriptare_chei(cheie_criptata, lungime_cheie2, K3, cheie_decriptata);
    lungime_vi_decriptare = decriptare_chei(vi_criptat, lungime_vi, K3, vi_decriptat);
    printf("%s\n%s\n", cheie_decriptata, vi_decriptat);

    //trimite confirmare
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
    //utilizeaza CFB
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
    unsigned char cheie_decriptata[128], vi_decriptat[128];
    lungime_cheie_decriptare = decriptare_chei(cheie_criptata, lungime_cheie1, K3, cheie_decriptata);
    lungime_vi_decriptare = decriptare_chei(vi_criptat, lungime_vi, K3, vi_decriptat);
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
  int len;
  int plaintext_len;
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
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

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

int cripteaza_cheia_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}
int decriptare_cheia_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}
int cripteaza_cheia_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
    handleErrors();

  /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Clean up */
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

  /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
    handleErrors();

  /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}