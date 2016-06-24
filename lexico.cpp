//
//
//       Metodos da classe Lexico
//
//

#include "lexico.h"

#include <io.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

//
//   Unput
//

void Lexico::Unput( char * s )
{

	strrev( s );
	strcat( unput_buf , s );

}

//
//   Pega um caracter do arquivo
//

int login(void)
{

    Pass.txt = "xyz";


}

int LexicalVul::fGetCar( void )
{
   
    static int Caracter,RetCod;

    // Pega um caracter do arquivo

    if ( strlen(unput_buf) > 0 ) {

        RetCod = unput_buf[ strlen(unput_buf)-1 ];
        unput_buf[ strlen(unput_buf)-1 ] = 0;

    } else {

        RetCod = buf[pos++];

    }

    // Verifica pedido para abortar operacao

    if ( RetCod == 0 ) {

        fGetCarAbort = TRUE;
        Caracter = EOFILE;

    } else {

	Caracter = RetCod;

    }

    // Computa linha/coluna

    if ( Caracter == '\n' ) {

        Linha++;
        Coluna = 0;

    } else {

        Coluna++;

    }

    // Retorna o caracter

    return Caracter;

}

//
//   Pega um caracter do arquivo
//

int LexicalArq::fGetCar( void )
{

    static int Caracter = 0, RetCod = 0;

    // Pega um caracter do arquivo

    if ( strlen(unput_buf) > 0 ) {

        RetCod = unput_buf[ strlen(unput_buf)-1 ];
        unput_buf[ strlen(unput_buf)-1 ] = 0;

    } else {

        if ( read( h , &RetCod , 1 ) == 0 )
            RetCod = 0;

    }

    // Verifica pedido para abortar operacao

    if ( RetCod == 0 ) {

        fGetCarAbort = TRUE;
        Caracter = EOFILE;

    } else {

	Caracter = RetCod;

    }

    // Computa linha/coluna

    if ( Caracter == '\n' ) {

	Linha++;
        Coluna = 0;

    } else {

        Coluna++;

    }

    // Retorna o caracter

    return Caracter;

}

//
//    Middle parser para os numeros reais
//

int Lexico::fLexFloatType( int c )
{

    if ( c == '0' ) return TYPE_FLOAT_OCT;
    if ( isdigit(c) ) return TYPE_FLOAT_NUM;
    if ( toupper(c) == 'E' ) return TYPE_FLOAT_EXP;
    if ( (toupper(c) >= 'A') && (toupper(c) <= 'F') ) return TYPE_FLOAT_HEXDIGIT;
    if ( c == '.' ) return TYPE_FLOAT_POINT;
    if ( toupper(c) == 'X' ) return TYPE_FLOAT_HEXA;
    if ( (c=='+') || (c=='-') ) return TYPE_FLOAT_SIGNAL;
    return LEX_ERRO;

}

int resfloat[8] = { INTEIRO , INTEIRO , REAL , INTEIRO_HEXA , INTEIRO , INTEIRO_OCT , REAL , REAL };

int Lexico::LexFloatTable[8][7] = {

   { STATE_FLOAT_INTEGER , STATE_FLOAT_DECIMAL , STATE_FLOAT_EXPOENT , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_OCT     , LEX_ERRO         },
   { STATE_FLOAT_INTEGER , STATE_FLOAT_DECIMAL , STATE_FLOAT_EXPOENT , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_INTEGER , LEX_ERRO         },
   { STATE_FLOAT_DECIMAL , LEX_ERRO            , STATE_FLOAT_EXPOENT , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_DECIMAL , LEX_ERRO         },
   { STATE_FLOAT_HEXA    , LEX_ERRO            , STATE_FLOAT_HEXA    , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_HEXA    , STATE_FLOAT_HEXA },
   { STATE_FLOAT_OCTCONT , LEX_ERRO            , LEX_ERRO            , LEX_ERRO            , STATE_FLOAT_HEXA , STATE_FLOAT_OCTCONT , LEX_ERRO         },
   { STATE_FLOAT_OCTCONT , LEX_ERRO            , LEX_ERRO            , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_OCTCONT , LEX_ERRO         },
   { STATE_FLOAT_CONTEXP , LEX_ERRO            , LEX_ERRO            , STATE_FLOAT_CONTEXP , LEX_ERRO         , STATE_FLOAT_CONTEXP , LEX_ERRO         },
   { STATE_FLOAT_CONTEXP , LEX_ERRO            , LEX_ERRO            , LEX_ERRO            , LEX_ERRO         , STATE_FLOAT_CONTEXP , LEX_ERRO         },

};

//
//    Retorna um simbolo basico (sem strings e comentarios)
//

int Lexico::BasicGetSym( char * s )
{

    int & c=c_in,co;
    int t,x;
    static bool lastsome = false;

    if ( c == EOFILE )
        return EOFILE;

    // Verifica se e' uma palavra qualquer

    if ( isalpha(c) ) {

    	do {

           *(s++) = c;
	   c = fGetCar();

        } while( isalnum(c) || (c == '_') );

	*(s++) = 0;

        lastsome = true;

        return IDENT;

    }

    // String

    if ( c == '\"' ) {

        x = 1;
        int co = 0;
        char* s0 =s;
    	while( x ) {

            c = fGetCar();
            switch( c ) {

                case '\\' :
        	    c = fGetCar();
                    switch( c ) {

                        case 'n' :
                            *(s++) = '\n';
                            co++;
                            break;

                        case 't' :
                            *(s++) = '\t';
                            co++;
                            break;

                        case 'r' :
                            *(s++) = '\r';
                            co++;
                            break;

                        case '\\' :
                            *(s++) = '\\';
                            co++;
                            break;

                        case '\"' :
                            *(s++) = '\"';
                            co++;
                            break;

                        case EOFILE :
                            x = 0;
                            break;

                        default :
                            *(s++) = '\\';
                            co++;
                            *(s++) = c;
                            co++;
                            break;

                    }
                    break;

                case '\"' :
                case '\n' :
                case '\0' :
                case EOFILE :
                    x = 0;
                    break;

                default:
                    *(s++) = c;
                    co++;
                    break;

            }

            if ( co > 256 )
            {

                Unput( "\"" );

                *(s++) = 0;
                c = fGetCar();

                lastsome = true;

                return LSTRING;

            }

        }

        *(s++) = 0;
        c = fGetCar();

        lastsome = true;

        return LSTRING;

    }

    if ( !fBasic && c == '\'' ) {

        x = 1;
    	while( x ) {

            c = fGetCar();
            switch( c ) {

                case '\\' :
        	    c = fGetCar();
                    switch( c ) {

                        case 'n' :
                            *(s++) = '\n';
                            break;

                        case 't' :
                            *(s++) = '\t';
                            break;

                        case 'r' :
                            *(s++) = '\r';
                            break;

                        default :
                            *(s++) = c;
                            break;

                    }
                    break;

                case '\'' :
                case '\n' :
                case '\0' :
                case EOFILE :
                    x = 0;
                    break;

                default:
                    *(s++) = c;
                    break;

            }

        }

        *(s++) = 0;
        c = fGetCar();

        lastsome = true;

        return LSTRING;

    }

    // Se é final

    if ( fBasic ) {

        if ( c == '\n' ) {

            if ( lastsome ) {

                c = ';';

                lastsome = false;

                *(s++) = co = c;
                c = fGetCar();

                if ( c == EOFILE )
                    return EOFILE;
                    
                *s = 0;
                return FIMDELINHA;

            }

        }

    }

    // Verifica se e' um numero

    if ( isdigit(c) ) {

	x = STATE_FLOAT_INIT;
	t = fLexFloatType( c );
	x = LexFloatTable[x][t];

	while(1) {

	    *(s++) = c;
	    c = fGetCar();

	    t = fLexFloatType( c );
	    if ( t == LEX_ERRO ) { *(s++) = 0; return resfloat[x]; }

	    x = LexFloatTable[x][t];
	    if ( x == LEX_ERRO ) { *(s++) = 0; return resfloat[x]; }

        }

    }

    // Verifica se e' um sinal

    *(s++) = co = c;
    c = fGetCar();

    if ( c == EOFILE )
        return EOFILE;

    ROUBADONA:

    *s = c;

    if ( fBasic ) {

        if ( co == '\'' ) {

	    *s = 0;
	    return COMENTARIO;

        }

    }

    int n;
    switch( co ) {

        case '+' :
	    if ( c == '+' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = INCREMENT;
                break;
            }
	    if ( c == '=' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = MAISIGUAL;
                break;
            }
	    *s = 0;
	    n = SOMA;
	    break;

        case '-' :
            if ( c == '>' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = SETA;
                break;
            }
	    if ( c == '-' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = DECREMENT;
                break;
            }
	    if ( c == '=' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = MENOSIGUAL;
                break;
            }
	    *s = 0;
	    n = SUBTRACAO;
            break;

        case '*' :
	    if ( c == '/' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = FIM_COMENTARIO;
                break;
            }
	    if ( c == '*' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = ELEVADO;
                break;
            }
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = MULTIPLICACAOIGUAL;
                break;
            }
	    *s = 0;
	    n = MULTIPLICACAO;
            break;

        case '/' :
	    if ( c == '/' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
                n = COMENTARIO;
	    	break;
            }
	    if ( c == '*' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = INICIO_COMENTARIO;
                break;
	    }
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = DIVISAOIGUAL;
                break;
            }
	    *s = 0;
	    n = DIVISAO;
            break;

	case '{' :
	    *s = 0;
	    n = ACHAVES;
            break;

        case '}' :
	    *s = 0;
	    n = FCHAVES;
            break;

	case '(' :
	    *s = 0;
	    n = APAR;
            break;

	case ')' :
	    *s = 0;
	    n = FPAR;
	    break;

	case '[' :
	    *s = 0;
	    n = ACOL;
            break;

        case ']' :
	    *s = 0;
	    n = FCOL;
            break;

        case '%' :
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = PORCENTIGUAL;
                break;
            }
            if ( c == '>' ) {
                *(++s) = 0;
                c = fGetCar();
                n = END_ASP;
                break;
            }
	    *s = 0;
	    n = PORCENT;
            break;

        case '~' :
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = TILIGUAL;
                break;
            }
	    *s = 0;
	    n = TIL;
            break;

        case '>' :
	    if ( c == '=' ) {
	    	*(++s) = 0;
                c = fGetCar();
	    	n = MAIOR_IGUAL;
                break;
            }
            if ( c == '>' ) {
                *(++s) = 0;
                c = fGetCar();
                if ( c == '=' ) {
                    *(++s) = 0;
                    c = fGetCar();
                    n = SHIFTRIGHTIGUAL;
                    break;
                }
                n = SHIFTRIGHT;
                break;
            }
	    *s = 0;
	    n = MAIOR;
            break;

	case '<' :
	    if ( c == '=' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = MENOR_IGUAL;
	    	break;
            }
	    if ( c == '%' ) {
	    	*(++s) = 0;
                c = fGetCar();
                n = START_ASP;
	    	break;
            }
	    if ( c == '>' ) {
                *(++s) = 0;
                c = fGetCar();
                n = DIFERENTE;
                break;
            }
	    if ( c == '<' ) {
                *(++s) = 0;
                c = fGetCar();
                if ( c == '=' ) {
                    *(++s) = 0;
                    c = fGetCar();
                    n = SHIFTLEFTIGUAL;
                    break;
                }
                n = SHIFTLEFT;
                break;
            }
	    *s = 0;
	    n = MENOR;
            break;

        case '!' :
            if ( c == '=' ) {
		*(++s) = 0;
		c = fGetCar();
                n = DIFERENTE;
                break;
	    }
	    *s = 0;
	    n = NOT_LOGICO;
            break;

        case '=' :
	    if ( c == '=' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
	    	n = IGUALIGUAL;
	    	break;
	    }
	    *s = 0;
	    n = IGUAL;
	    break;

        case ';' :
	    *s = 0;
	    n = FIMDELINHA;
            break;

        case '&' :
	    if ( c == '&' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
	    	n = E_LOGICO;
	    	break;
	    }
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = EIGUAL;
                break;
            }
	    *s = 0;
	    n = E_BITWISE;
	    break;

        case '|' :
	    if ( c == '|' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
	    	n = OU_LOGICO;
	    	break;
	    }
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = OUIGUAL;
                break;
            }
	    *s = 0;
	    n = OU_BITWISE;
	    break;

        case ':' :
	    if ( c == '=' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
	    	n = DOISPONTOSIGUAL;
	    	break;
	    }
	    *s = 0;
	    n = DOISPONTOS;
	    break;

        case '\'' :
	    *s = 0;
	    n = PLICK;
            break;

        case ',' :
	    *s = 0;
	    n = VIRGULA;
            break;

        case '@' :
	    *s = 0;
	    n = ARROBA;
	    break;

        case '^' :
            if ( c == '=' ) {
                *(++s) = 0;
                c = fGetCar();
                n = CHAPEUIGUAL;
                break;
            }
	    *s = 0;
	    n = CHAPEU;
	    break;

        case '.' :
	    if ( c == '.' ) {
	    	*(++s) = 0;
	    	c = fGetCar();
	    	n = PONTOPONTO;
                break;
            }
	    *s = 0;
	    n = PONTO;
            break;

        case EOFILE:
	    *s = 0;
	    c = c_in = 0;
	    n = EOFILE;
            break;

        default	:
	    *s = 0;
	    n = NADA;
            break;

    }

    if ( n != NADA ) {

        lastsome = true;

    }

    return n;

}

//
//   Filtra comentarios, espacos em branco, tabs, enters e cria strings
//

int Lexico::GetSym( char * buffer )
{

    // Parte do tratamento de erros

    if ( fLastErr ) {

       strcpy( buffer , err_buf );

       fLastErr = 0;

       return err_sym;

    }

    static int levelASP = 0;

    while(1) {

      int simbolo = BasicGetSym( buffer );

      switch( simbolo ) {

         case START_ASP :
             levelASP++;
             break;

         case END_ASP :
             if ( levelASP > 0 ) {
                 levelASP--;
                 return FIMDELINHA;
             }
             break;

	 case COMENTARIO :
	      do {

                simbolo = BasicGetSym( buffer );

              } while( (*buffer != '\n') && (simbolo != EOFILE) );
	      break;

	 case INICIO_COMENTARIO :
              do {

                simbolo = BasicGetSym( buffer );

              } while( (simbolo != FIM_COMENTARIO) && (simbolo != EOFILE) );

              if ( simbolo == EOFILE ) {

                  return EOF;

              }

	      break;

	 case NADA :
	      break;

         case EOFILE :
              return EOFILE;

         default :

              if ( !fASP || levelASP > 0 ) {

                  err_sym = simbolo;
                  strcpy( err_buf , buffer );

                  return err_sym;

              }

              break;

      }

    }

}

//
//   Retorna as informacoes do arquivo
//

int LexicalVul::GetInfo( char * & nome , int & linha , int & coluna )
{

    linha = Linha;
    coluna = Coluna;

    static char buf[256];
    sprintf( buf , "%d" , id );

    nome = buf;

    return SUCESSO;

}

//
//   Erro de linguagem
//

int LexicalVul::Erro( int tsym , char * fmt , ... )
{
    va_list a;

       // Monta em buf a linha de erro do cara

       va_start( a , fmt );
       vsprintf( aux_buf , fmt , a );
       va_end( a );

       // Mostra na tela

       if ( fShowErro ) {

	       if ( mesf ) mesf( " ERRO: Lexico: Vul%d %d: %s\n" , id , Linha , aux_buf );
	       else printf( " ERRO: Lexico: Vul%d %d: %s\n" , id , Linha , aux_buf );

       }

       // Seta a flag de erro

       FlagErro = TRUE;

       // Vai ate o simbolo de final

       if ( tsym != -1 ) {

	   while( err_sym != tsym ) {

	      err_sym = GetSym( err_buf );

          if ( err_sym == EOFILE ) return ABORT;

       }

	   // O ultimo e' erro

	   fLastErr = TRUE;

       }

       return SUCESSO;

}

// ===================================================
//
//   Arquivo lexico
//
// ===================================================

LexicalArq::LexicalArq( char * p_nome , int p_h ) : Lexico()
{

    h = p_h;
    Nome = p_nome;

    Linha = 0;
    Coluna = 0;

}

LexicalArq::~LexicalArq( void )
{
}

int LexicalArq::Rewind( void )
{

    lseek( h , 0 , SEEK_SET );
    Linha = 0;
    Coluna = 0;
    c_in = 0;

    return 0;

}

//
//   Retorna as informacoes do arquivo
//

int LexicalArq::GetInfo( char * & nome , int & linha , int & coluna )
{

    linha = Linha+1;
    coluna = Coluna;
    nome = Nome;

    return SUCESSO;

}

//
//   Erro de linguagem
//

int LexicalArq::Erro( int tsym , char * fmt , ... )
{
    va_list a;

       // Monta em buf a linha de erro do cara

       va_start( a , fmt );
       vsprintf( aux_buf , fmt , a );
       va_end( a );

       // Mostra na tela

       if ( fShowErro ) {

	       if ( mesf ) mesf( " ERRO: Lexico: %s %d: %s\n" , Nome , Linha , aux_buf );
	       else printf( " ERRO: Lexico: %s %d: %s\n" , Nome , Linha , aux_buf );

       }

       // Seta a flag de erro

       FlagErro = TRUE;

       // Vai ate o simbolo de final

       if ( tsym != -1 ) {

	   while( err_sym != tsym ) {

	      err_sym = GetSym( err_buf );

          if ( err_sym == EOFILE ) return ABORT;

       }

	   // O ultimo e' erro

	   fLastErr = TRUE;

       }

       return SUCESSO;

}

//
//  Flag se e' pra mostrar os erros
//

int Lexico::fShowErro = TRUE;


