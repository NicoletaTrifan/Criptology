#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#define PORT 2020
/*codul de eroare returnat de anumite apeluri*/
extern int errno;

typedef struct thData
{
	int idThread; //id-ul thread-ului tinut in evidenta de acest program
	int cl;		  //descriptorul intors de accept
} thData;

static void *treat(void *); //Functia executata de fiecare thread ce realizeaza conexiunea
void raspunde(void *);
void transmitere_chei(void *arg); // se apeleaza dupa ce serverul primeste optiunea de criptare
void handleErrors(void);
int cripteaza_cheia(unsigned char *plaintext, int plaintext_len, unsigned char *key,
					unsigned char *ciphertext);
int decriptare_chei(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
					unsigned char *plaintext);
unsigned char **impartire_blocuri(unsigned char *mesaj, int nr_blocuri);
void **impartire_blocuri_decriptare(unsigned char *mesaj, int nr_blocuri, unsigned char **blocuri); // o folosesc la decriptare; blocurile sunt fara padding
int cripteaza_cheia_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
int cripteaza_cheia_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *ciphertext);
int decriptare_cheia_cfb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                         unsigned char *iv, unsigned char *plaintext);
unsigned char *xor_function(unsigned char *plaintext, unsigned char *initialization_vector);
//Key Manager contine toate cheile si vectorul de initializare
unsigned char *K1 = (unsigned char *)"BFE2BF904559FAB2";
unsigned char *K2 = (unsigned char *)"A11202C9B468BEA1";
unsigned char *K3 = (unsigned char *)"0011223344556677";
unsigned char *IV = (unsigned char *)"FFEEDDCCBBAA9988";
int descriptor[2];
int nr_optiune; //optiunea aleasa de client pentru criptare
int main()
{
	struct sockaddr_in server; // structura folosita de server
	struct sockaddr_in from;
	int sd; //descriptorul de socket
	int pid;
	pthread_t th[2]; //Identificatorii thread-urilor care se vor crea
	int i = 0;

	/* crearea unui socket */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("[server]Eroare la socket().\n");
		return errno;
	}
	/* utilizarea optiunii SO_REUSEADDR (bind will fail without that)*/
	int on = 1;
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* pregatirea structurilor de date */
	bzero(&server, sizeof(server));
	bzero(&from, sizeof(from));

	/* umplem structura folosita de server */
	/* stabilirea familiei de socket-uri */
	server.sin_family = AF_INET;
	/* acceptam orice adresa */
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	/* utilizam un port utilizator */
	server.sin_port = htons(PORT);

	/* atasam socketul */
	if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
	{
		perror("[server]Eroare la bind().\n");
		return errno;
	}

	/* punem serverul sa asculte daca vin clienti sa se conecteze */
	if (listen(sd, 2) == -1)
	{
		perror("[server]Eroare la listen().\n");
		return errno;
	}
	/* servim in mod concurent clientii...folosind thread-uri */
	while (1)
	{
		int client;
		thData *td; //parametru functia executata de thread
		int length = sizeof(from);

		printf("[server]Asteptam conectarea clientilor la portul %d\n", PORT);
		fflush(stdout);
		/* acceptam un client (stare blocanta pina la realizarea conexiunii) */
		if ((client = accept(sd, (struct sockaddr *)&from, &length)) < 0)
		{
			perror("[server]Eroare la accept().\n");
			continue;
		}

		/* s-a realizat conexiunea, se astepta mesajul */
		//memorez descriptorii pt ai folosi mai apoi la primirea si transmiterea de mesaje
		descriptor[i] = client;
		td = (struct thData *)malloc(sizeof(struct thData));
		td->idThread = i++;
		printf("%d", client);
		td->cl = client;
		pthread_create(&th[i - 1], NULL, &treat, td);
	}
};
static void *treat(void *arg)
{
	struct thData tdL;
	tdL = *((struct thData *)arg);
	printf("[thread]- %d - Asteptam mesajul...\n", tdL.idThread);
	fflush(stdout);
	pthread_detach(pthread_self());
	raspunde((struct thData *)arg);
	/* am terminat cu acest client, inchidem conexiunea */
	close((intptr_t)arg);
	return (NULL);
};

void raspunde(void *arg)
{
	int i = 0;
	struct thData tdL;
	tdL = *((struct thData *)arg);
	// printf("%d\n", tdL.cl);
	// printf("%d\n", *descriptor);
	if (tdL.cl == descriptor[0])
	{
		char mesaj_initialA[] = "Alegeti modul de criptare CBC(0)/CFB(1). Tastati optiunea conform modului de criptare preferat\n";
		if (write(descriptor[0], mesaj_initialA, sizeof(mesaj_initialA)) <= 0)
		{
			printf("[Thread %d] ", tdL.idThread);
			perror("[Thread]Eroare la write() catre client1.\n");
		}
		else
			printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

		if (read(descriptor[0], &nr_optiune, sizeof(int)) <= 0)
		{
			printf("[Thread %d] ", tdL.idThread);
			perror("[Thread]Eroare la read() catre client2.\n");
		}
		else
			printf("[Thread %d]Optiunea aleasa de nodul A este %d\n", tdL.idThread, nr_optiune);
		if (nr_optiune == 0)
			printf("[Thread %d]A ales criptarea CBC\n", tdL.idThread);
		else if (nr_optiune == 1)
			printf("[Thread %d]A ales criptarea CFB\n", tdL.idThread);
		//pot apela o functie
		transmitere_chei((struct thData *)arg);
	}
	else
	{
		char mesaj_initialB[] = "Asteptati nodul A sa faca alegerea";
		if (write(descriptor[1], mesaj_initialB, sizeof(mesaj_initialB)) <= 0)
		{
			printf("[Thread %d] ", tdL.idThread);
			perror("[Thread]Eroare la write() catre client.\n");
		}
		else
			printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
		sleep(10); // Il fac sa astepte cu executia apelului pana reuseste nodul A sa aleaga
		transmitere_chei((struct thData *)arg);
	}
}
void transmitere_chei(void *arg)
{
	struct thData tdL;
	tdL = *((struct thData *)arg);
	printf("%d", nr_optiune);
	if (nr_optiune == 0)
	{ //CBC
		if (tdL.cl == descriptor[0])
		{ //client A
			//transmitem lui A cheia criptata in mod ecb si vectorul de initializare
			//client A
			unsigned char cheie_criptata[16];
			unsigned char vi_criptat[16];
			int lungime_cheie = strlen(K1);
			int lungime_vi = strlen(IV);
			int lungime_cheie_criptata, lungime_vi_criptat;
			lungime_cheie_criptata = cripteaza_cheia(K1, lungime_cheie, K3, cheie_criptata);
			lungime_vi_criptat = cripteaza_cheia(IV, lungime_vi, K3, vi_criptat);
			//transmitem mai intai nodului A lungimea cheii
			if (write(descriptor[0], &lungime_cheie_criptata, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem cheia criptata
			if (write(descriptor[0], cheie_criptata, lungime_cheie_criptata) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
			//transmitem mai intai lungimea vectorului de initializare
			if (write(descriptor[0], &lungime_vi_criptat, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem VI criptat
			if (write(descriptor[0], vi_criptat, lungime_vi_criptat) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			int lungime_confirmare;
			if (read(descriptor[0], &lungime_confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			unsigned char confirmare_criptat[lungime_confirmare];
			if (read(descriptor[0], confirmare_criptat, lungime_confirmare) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			int lungime_confirmat_decriptat; 
			unsigned char confirmare_decriptat[10];
			lungime_confirmat_decriptat = decriptare_cheia_cbc(confirmare_criptat, lungime_confirmare, K1, IV, confirmare_decriptat);
			printf("%s\n", confirmare_decriptat);

		}
		else
		{ //client B
			int optiune_ramasa = 1, confirmare;
			char mesaj_alegere[] = "Nodul A a ales modul CBC. Confirmati prin 1 utilizarea modului CFB :";
			if (write(descriptor[1], mesaj_alegere, sizeof(mesaj_alegere)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			if (read(descriptor[1], &confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			else
				printf("[Thread %d]B a confirmat \n", tdL.idThread);

			if (write(descriptor[1], &optiune_ramasa, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			unsigned char cheie_criptata[16];
			unsigned char vi_criptat[16];
			int lungime_cheie = strlen(K2);
			int lungime_vi = strlen(IV);
			int lungime_cheie_criptata, lungime_vi_criptat;
			lungime_cheie_criptata = cripteaza_cheia(K2, lungime_cheie, K3, cheie_criptata);
			lungime_vi_criptat = cripteaza_cheia(IV, lungime_vi, K3, vi_criptat);
			//transmitem mai intai nodului A lungimea cheii
			if (write(descriptor[1], &lungime_cheie_criptata, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem cheia criptata
			if (write(descriptor[1], cheie_criptata, lungime_cheie_criptata) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
			//transmitem mai intai lungimea vectorului de initializare
			if (write(descriptor[1], &lungime_vi_criptat, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem VI criptat
			if (write(descriptor[1], vi_criptat, lungime_vi_criptat) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			int lungime_confirmare;
			if (read(descriptor[1], &lungime_confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			unsigned char confirmare_criptat[lungime_confirmare];
			if (read(descriptor[1], confirmare_criptat, lungime_confirmare) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			int lungime_confirmat_decriptat; 
			unsigned char *confirmare_decriptat;
			lungime_confirmat_decriptat = decriptare_cheia_cfb(confirmare_criptat, lungime_confirmare, K2, IV, confirmare_decriptat);
			printf("%s\n", confirmare_decriptat);
		}
	}
	else
	{ //CFB
		if (tdL.cl == descriptor[0])
		{ //client A
			unsigned char cheie_criptata[16];
			unsigned char vi_criptat[16];
			int lungime_cheie = strlen((char *)K2);
			int lungime_vi = strlen(IV);
			int lungime_cheie_criptata, lungime_vi_criptat;
			lungime_cheie_criptata = cripteaza_cheia(K2, lungime_cheie, K3, cheie_criptata);
			lungime_vi_criptat = cripteaza_cheia(IV, lungime_vi, K3, vi_criptat);
			//transmitem mai intai nodului A lungimea cheii
			if (write(descriptor[0], &lungime_cheie_criptata, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem cheia criptata
			if (write(descriptor[0], cheie_criptata, lungime_cheie_criptata) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
			//transmitem mai intai lungimea vectorului de initializare
			if (write(descriptor[0], &lungime_vi_criptat, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem VI criptat
			if (write(descriptor[0], vi_criptat, lungime_vi_criptat) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
			
			int lungime_confirmare;
			if (read(descriptor[0], &lungime_confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			unsigned char confirmare_criptat[lungime_confirmare];
			if (read(descriptor[0], confirmare_criptat, lungime_confirmare) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			int lungime_confirmat_decriptat; 
			unsigned char *confirmare_decriptat;
			lungime_confirmat_decriptat = decriptare_cheia_cbc(confirmare_criptat, lungime_confirmare, K2, IV, confirmare_decriptat);
			printf("%s\n", confirmare_decriptat);

		}
		else
		{ //client B
			int confirmare;
			int optiune_ramasa = 0;
			char mesaj_alegere[] = "Nodul A a ales modul CFB. Confirmati prin 1 utilizarea modului CBC si prin 0 utilizarea modului CBC:";
			if (write(descriptor[1], mesaj_alegere, sizeof(mesaj_alegere)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			if (read(descriptor[1], &confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			else
				printf("[Thread %d]B a confirmat \n", tdL.idThread);

			if (write(descriptor[1], &optiune_ramasa, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//trimitem cheile corespunzatoare modului de operare
			unsigned char cheie_criptata[16];
			unsigned char vi_criptat[16];
			int lungime_cheie = strlen(K1);
			int lungime_vi = strlen(IV);
			int lungime_cheie_criptata, lungime_vi_criptat;
			lungime_cheie_criptata = cripteaza_cheia(K1, lungime_cheie, K3, cheie_criptata);
			lungime_vi_criptat = cripteaza_cheia(IV, lungime_vi, K3, vi_criptat);
			//transmitem mai intai nodului A lungimea cheii
			if (write(descriptor[1], &lungime_cheie_criptata, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem cheia criptata
			if (write(descriptor[1], cheie_criptata, lungime_cheie_criptata) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
			//transmitem mai intai lungimea vectorului de initializare
			if (write(descriptor[1], &lungime_vi_criptat, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);

			//transmitem VI criptat
			if (write(descriptor[1], vi_criptat, lungime_vi_criptat) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la write() catre client.\n");
			}
			else
				printf("[Thread %d]Mesajul a fost trasmis cu succes.\n", tdL.idThread);
		
			int lungime_confirmare;
			if (read(descriptor[1], &lungime_confirmare, sizeof(int)) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			unsigned char confirmare_criptat[lungime_confirmare];
			if (read(descriptor[1], confirmare_criptat, lungime_confirmare) <= 0)
			{
				printf("[Thread %d] ", tdL.idThread);
				perror("[Thread]Eroare la read() catre client.\n");
			}
			int lungime_confirmat_decriptat; 
			unsigned char *confirmare_decriptat;
			lungime_confirmat_decriptat = decriptare_cheia_cbc(confirmare_criptat, lungime_confirmare, K2, IV, confirmare_decriptat);
			printf("%s\n", confirmare_decriptat);
		}
	}
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
//criptam cheia cu aceasta functie cu K3
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