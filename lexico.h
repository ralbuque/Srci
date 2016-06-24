//
//    Classe LexicalArq (para leitura de arquivos)
//

#ifndef LEXICO_H
#define LEXICO_H

#include <stdio.h>

// Codigo de erro universal

#define LEX_ERRO -1
#define SUCESSO 0
#define ABORT 1

#define TRUE 1
#define FALSE 0

// Defines para parser de float

enum { STATE_FLOAT_INIT , STATE_FLOAT_INTEGER , STATE_FLOAT_DECIMAL , STATE_FLOAT_HEXA , STATE_FLOAT_OCT , STATE_FLOAT_OCTCONT , STATE_FLOAT_EXPOENT , STATE_FLOAT_CONTEXP };
enum { TYPE_FLOAT_NUM , TYPE_FLOAT_POINT , TYPE_FLOAT_EXP , TYPE_FLOAT_SIGNAL , TYPE_FLOAT_HEXA , TYPE_FLOAT_OCT , TYPE_FLOAT_HEXDIGIT };

// Classe LexicalArq

class Lexico {

       private :

           // Tabela de transicoes de estados para parser de floats

           static int LexFloatTable[8][7];

           // Parser para floats

           int fLexFloatType( int );

           // Calcula simbolo basico

           int BasicGetSym( char * );

           // Retorna um caracter

           virtual int fGetCar( void ) = 0;

           bool fBasic;
           bool fASP;

       protected :

           // Proximo caracter/simbolo

           int c_in;

           // Buffers para tratamento de erro

           char err_buf[300];
           int  err_sym;
           char aux_buf[100];
		   int  fLastErr;
	       int  nErr;
		   char unput_buf[4096];

           static int fShowErro;

           // Flag para bypassar erro pela 'BasicGetSym'

           int fGetCarAbort;

	       // Contador para linha/coluna

           int Linha,Coluna;

           // Flag para indicar erro

		   int FlagErro;

	       // Ponteiro pra funcao substitui o printf

	       void (* mesf)( char * , ... );

       public :

           // Inicializa a classe

           Lexico( void )
           {
               c_in = 0;
               fGetCarAbort = FALSE;
               fShowErro = TRUE;
               FlagErro = FALSE;
               fLastErr = FALSE;
               Linha = Coluna = 0;
               err_sym = 0;
               mesf = 0;
               nErr = 0;
               unput_buf[0] = 0;
               fBasic = false;
               fASP = false;
           }

           // Bypassa para as correspondentes em Arq

           virtual int Abre( void ) { return SUCESSO; };
           virtual int Fecha( void ) { return SUCESSO; };

           void SetBasic( bool fb ) { fBasic = fb; }
           void SetASP( bool fb ) { fASP = fb; }

		   // Unput

		   void Unput( char * s );

           // Funcao util

           int GetSym( char * );

	       // Retorna linha, coluna e nome do arquivo

           virtual int GetInfo( char * & , int & , int & ) = 0;
           virtual int Rewind( void ) = 0;

           virtual int Erro( int , char * , ... ) = 0;

           // Flag de erro

           int GetErro( int & e ) { e = FlagErro; return SUCESSO; }
	       int SetErro( int e , void (* m)( char * , ... ) = NULL ) { fShowErro = e; mesf = m; return SUCESSO; }

};

//  Defines dos tipos de simbolos

enum { EOFILE=-1 , NADA , IDENT , REAL , INTEIRO , INTEIRO_HEXA , INTEIRO_OCT , MMAIOR , MAIOR , MMENOR , MENOR ,
       INCREMENT , INCRSOMA , SOMA , DECREMENT , DECRSOMA , SETA , SUBTRACAO ,
       MULTSOMA , FIM_COMENTARIO , MULTIPLICACAO , DIVSOMA , MENOS_UNARIO ,
       INICIO_COMENTARIO , COMENTARIO , DIVISAO , ASPAS , PLICK , PONTO ,
       PONTOPONTO , LSTRING , ACHAVES , FCHAVES , APAR , FPAR , ACOL , FCOL , IGUAL ,
       GETOLD , DOISPONTOS , VIRGULA , MAIOR_IGUAL , MENOR_IGUAL , DIFERENTE ,
       NOT , AND , OR , FIMDELINHA , ARROBA , CHAPEU , DOISPONTOSIGUAL , IGUALIGUAL ,
       E_LOGICO , OU_LOGICO , NOT_LOGICO , E_BITWISE , OU_BITWISE , ELEVADO , PORCENT , TIL ,
       MAISIGUAL , MENOSIGUAL , SHIFTLEFT , SHIFTRIGHT , PORCENTIGUAL , SHIFTLEFTIGUAL , SHIFTRIGHTIGUAL , TILIGUAL ,
       DIVISAOIGUAL , MULTIPLICACAOIGUAL , EIGUAL , OUIGUAL , CHAPEUIGUAL , START_ASP , END_ASP };

//
//   Caso de lexico de vulnerabilidade
//

class LexicalVul : public Lexico {

    private :

        // Arquivo

	char * buf;
	unsigned long pos;

	int id;
	int lin_ini;

	// Retorna um caracter

	int fGetCar( void );

    public :

        LexicalVul( char * p_buf , int p_id , int p_lin_ini ) : Lexico()
	{

	    id = p_id;
            buf = p_buf;
            lin_ini = p_lin_ini;
            pos = 0;

            Linha = lin_ini;
            Coluna = 0;

        }

	~LexicalVul( void )
        {
        }

        int Rewind( void ) { pos = 0; Linha = lin_ini; Coluna = 0; return 0; }

	int GetInfo( char * & , int & , int & );
	int Erro( int , char * , ... );

};

//
//   Caso de lexico de arquivo já aberto
//

class LexicalArq : public Lexico {

    private :

        // Arquivo

        int h;
        char * Nome;

        // Retorna um caracter

        int fGetCar( void );

    public :

	LexicalArq( char * p_nome , int p_h );
        ~LexicalArq( void );
        int Rewind( void );

        int GetInfo( char * & , int & , int & );
        int Erro( int , char * , ... );

};

#endif
