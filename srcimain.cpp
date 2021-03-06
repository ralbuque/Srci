//---------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <dos.h>
#include <dir.h>
#include <io.h>
#include <fcntl.h>
#pragma hdrstop

#include "lexico.h"
#include "sha.h"

//---------------------------------------------------------------------------
void ErroFatal( void )
{

    strcpy( x , y );

    abort();

}
//---------------------------------------------------------------------------
// Gera��o da tabela
FILE * fi = NULL;
FILE * fv = NULL;
//---------------------------------------------------------------------------
// Linguagem
enum { CHECK , C , CPP , PAS , JAVA , BAS , ASP , CSHARP , PHP , NUM_LINGUAGENS };
int iLinguagem;
//---------------------------------------------------------------------------
// Erros
enum { ERRO_ARGUMENTO_INVALIDO = 1 , ERRO_PARAMETRO_INVALIDO , ERRO_LINGUAGEM_NAO_IDENTIFICADA };
int iErro;
//---------------------------------------------------------------------------
enum { TIPO_POSITIVO , TIPO_NEGATIVO , TIPO_NEGATIVO_IDENT };
//---------------------------------------------------------------------------
struct TokenMask {

    int tipo;

    int nsym;
    int * sym;
    char * * ident;

};
//---------------------------------------------------------------------------
struct Assinatura {

    int nToken;
    TokenMask * token;

};
//---------------------------------------------------------------------------
enum { CLASSE_ATAQUE_DIRETO };
//---------------------------------------------------------------------------
struct Vulnerabilidade {

    int id;
    char * nome;
    char * descricao;

    int classe;

    int nAssinatura;
    Assinatura * assinatura;

    int nLinguagem;
    int * linguagem;

};
//---------------------------------------------------------------------------
int nVulnerabilidade;
Vulnerabilidade * vulnerabilidade;
//---------------------------------------------------------------------------
Vulnerabilidade * AddVulnerabilidade( int id , char * nome , char * descricao , int classe , int linguagem )
{

    int n = -1;

    for( int i = 0 ; i < nVulnerabilidade ; i++ ) {

        if ( vulnerabilidade[i].id == id ) {

            n = i;
            break;

        }

    }

    if ( n == -1 ) {

        if ( nVulnerabilidade % 32 == 0 ) {

            vulnerabilidade = (Vulnerabilidade *)realloc( vulnerabilidade , (nVulnerabilidade+32) * sizeof(Vulnerabilidade) );
            if ( !vulnerabilidade )
                ErroFatal();

        }

        n = nVulnerabilidade++;

        memset( &(vulnerabilidade[n]) , 0 , sizeof(Vulnerabilidade) );

    }

    if ( vulnerabilidade[n].nome )
        free( vulnerabilidade[n].nome );

    vulnerabilidade[n].nome = strdup( nome );

    if ( vulnerabilidade[n].descricao )
        free( vulnerabilidade[n].descricao );

    vulnerabilidade[n].descricao = strdup( descricao );

    vulnerabilidade[n].classe = classe;

    bool tem = false;
    for( int j = 0 ; j < vulnerabilidade[n].nLinguagem ; j++ )
        if ( vulnerabilidade[n].linguagem[j] == linguagem )
            tem = true;

    if ( !tem ) {

        vulnerabilidade[n].linguagem = (int *)realloc( vulnerabilidade[n].linguagem , (vulnerabilidade[n].nLinguagem+1)*sizeof(int) );
        vulnerabilidade[n].linguagem[vulnerabilidade[n].nLinguagem++] = linguagem;

    }

    return &(vulnerabilidade[n]);

}
//---------------------------------------------------------------------------
enum { CONCATENACAO_STRINGS = 1 , RETORNO_FUNCAO_SEM_CHECK , USO_TRACE , IGNORAR_EXCECAO , USO_IF_FIXO , USO_RETURN_FIXO , INCLUDE_VARIAVEL , FUNCAO_EVAL };
//---------------------------------------------------------------------------
Assinatura * AddAssinatura( Vulnerabilidade * vulnerabilidade )
{

    if ( vulnerabilidade->nAssinatura % 32 == 0 ) {

        vulnerabilidade->assinatura = (Assinatura *)realloc( vulnerabilidade->assinatura , (vulnerabilidade->nAssinatura+32) * sizeof(Assinatura) );
        if ( !vulnerabilidade->assinatura )
            ErroFatal();

    }

    memset( &(vulnerabilidade->assinatura[vulnerabilidade->nAssinatura]) , 0 , sizeof(Assinatura) );

    return &(vulnerabilidade->assinatura[vulnerabilidade->nAssinatura++]);

}
//---------------------------------------------------------------------------
void AddMask( TokenMask * token , int sym , char * ident )
{

    if ( token->nsym % 32 == 0 ) {

        token->sym = (int *)realloc( token->sym , (token->nsym+32) * sizeof(int) );
        if ( !token->sym )
            ErroFatal();

        token->ident = (char * *)realloc( token->ident , (token->nsym+32) * sizeof(int) );
        if ( !token->ident )
            ErroFatal();

    }

    token->sym[ token->nsym ] = sym;

    if ( ident )
        token->ident[ token->nsym ] = strdup( ident );
    else
        token->ident[ token->nsym ] = NULL;

    token->nsym++;

}
//---------------------------------------------------------------------------
TokenMask * AddTokenMask( Assinatura * assinatura , int token , char * ident , int tipo )
{

    if ( assinatura->nToken % 32 == 0 ) {

        assinatura->token = (TokenMask *)realloc( assinatura->token , (assinatura->nToken+32) * sizeof(TokenMask) );
        if ( !assinatura->token )
            ErroFatal();

    }

    memset( &(assinatura->token[assinatura->nToken]) , 0 , sizeof(TokenMask) );

    assinatura->token[assinatura->nToken].tipo = tipo;
    AddMask( &(assinatura->token[assinatura->nToken]) , token , ident );

    return &(assinatura->token[assinatura->nToken++]);

}
//---------------------------------------------------------------------------
void MontaTabelaVulnerabilidade( void )
{

    //
    //   Vulnerabilidades do Java
    //

    Vulnerabilidade * v;
    Assinatura * a;
    TokenMask * t;

    // ***** JAVA *****

    // Concatena��o de string

    v = AddVulnerabilidade( CONCATENACAO_STRINGS , "Concatenacao de Strings" , "Concatenacao de strings pode levar a SQL Injection" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , LSTRING , NULL , TIPO_POSITIVO );
    AddTokenMask( a , SOMA    , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // Falta de teste de retorno de fun��o

    v = AddVulnerabilidade( RETORNO_FUNCAO_SEM_CHECK , "Ausencia de teste de retorno de funcao" , "Falta de teste de retorno pode ocasionar ataques por comprometimento da camada subjacente" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , FIMDELINHA , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT      , "if;while;for" , TIPO_NEGATIVO_IDENT );
    AddTokenMask( a , APAR       , NULL , TIPO_POSITIVO );

    // Uso de trace

    v = AddVulnerabilidade( USO_TRACE , "Uso de trace em producao" , "Uso de Trace em aplicativos em producao pode fornecer informacoes indevidas ao eventual atacante" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "System" , TIPO_POSITIVO );
    AddTokenMask( a , PONTO , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , "out" , TIPO_POSITIVO );
    AddTokenMask( a , PONTO , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , IDENT , "println" , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , IDENT , "print" );

    // Ignorar exce��o

    v = AddVulnerabilidade( IGNORAR_EXCECAO , "Exception sendo ignorada" , "Exception nao esta sendo tratada de forma nenhuma, gerando uma oportunidade de ataque" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "catch" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , FPAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , ACHAVES , NULL , TIPO_POSITIVO );
    AddTokenMask( a , FCHAVES , NULL , TIPO_POSITIVO );

    // Segunda assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "catch" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , FPAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , ACHAVES , NULL , TIPO_POSITIVO );
    AddTokenMask( a , FCHAVES , NULL , TIPO_POSITIVO );

    // IFs diretos

    v = AddVulnerabilidade( USO_IF_FIXO , "Comparacao com valores fixos" , "Condicoes com comparacao com valor fixo pode indicar codigo malicioso" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "if" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUALIGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Return diretos

    v = AddVulnerabilidade( USO_RETURN_FIXO , "Retorno fixo de valores" , "Funcao esta retornando valores fixos, pode indicar codigo malicioso" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "return" , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );
    AddTokenMask( a , FIMDELINHA , NULL , TIPO_POSITIVO );

    // ***** PHP *****

    // Concatena��o de string

    v = AddVulnerabilidade( CONCATENACAO_STRINGS , "Concatenacao de Strings" , "Concatenacao de strings pode levar a SQL Injection" , CLASSE_ATAQUE_DIRETO , PHP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , LSTRING , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // Include variavel

    v = AddVulnerabilidade( INCLUDE_VARIAVEL , "Include variavel" , "Include de variavel fornecida pelo usuario permite visualizacao de dados indevidos" , CLASSE_ATAQUE_DIRETO , PHP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "include" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE   , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // Segunda assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "include_only" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE   , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // Uso de fun��o EVAL

    v = AddVulnerabilidade( FUNCAO_EVAL , "Funcao Eval" , "Funcao eval pode gerar falhas e fragilidade de seguranca" , CLASSE_ATAQUE_DIRETO , PHP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "eval" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );

    // Concatena��o de string

    v = AddVulnerabilidade( CONCATENACAO_STRINGS , "SQL Injection" , "Concatenacao de strings pode levar a SQL Injection" , CLASSE_ATAQUE_DIRETO , JAVA );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "WHERE" , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    AddTokenMask( a , PLICK , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE   , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // Segunda assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "SET" , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    AddTokenMask( a , PLICK , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE   , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // ***** ASP *****

    // Concatena��o de string

    v = AddVulnerabilidade( CONCATENACAO_STRINGS , "Concatenacao de Strings" , "Concatenacao de strings pode levar a SQL Injection" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , LSTRING , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // IFs diretos

    v = AddVulnerabilidade( USO_IF_FIXO , "Comparacao com valores fixos" , "Condicoes com comparacao com valor fixo pode indicar codigo malicioso" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "if" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "if" , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "If" , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "If" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Falta de teste de retorno de fun��o

    v = AddVulnerabilidade( RETORNO_FUNCAO_SEM_CHECK , "Ausencia de teste de retorno de funcao" , "Falta de teste de retorno pode ocasionar ataques por comprometimento da camada subjacente" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , FIMDELINHA , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT      , "if;while;for" , TIPO_NEGATIVO_IDENT );
    AddTokenMask( a , APAR       , NULL , TIPO_POSITIVO );

    // ***** VISUAL BASIC *****

    // Concatena��o de string

    v = AddVulnerabilidade( CONCATENACAO_STRINGS , "Concatenacao de Strings" , "Concatenacao de strings pode levar a SQL Injection" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , LSTRING , NULL , TIPO_POSITIVO );
    AddTokenMask( a , E_BITWISE , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT   , NULL , TIPO_POSITIVO );

    // IFs diretos

    v = AddVulnerabilidade( USO_IF_FIXO , "Comparacao com valores fixos" , "Condicoes com comparacao com valor fixo pode indicar codigo malicioso" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "if" , TIPO_POSITIVO );
    AddTokenMask( a , APAR , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , IDENT , "if" , TIPO_POSITIVO );
    AddTokenMask( a , IDENT , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IGUAL , NULL , TIPO_POSITIVO );
    t = AddTokenMask( a , REAL , NULL , TIPO_POSITIVO );  // Alternativamente...
             AddMask( t , LSTRING , NULL );

    // Falta de teste de retorno de fun��o

    v = AddVulnerabilidade( RETORNO_FUNCAO_SEM_CHECK , "Ausencia de teste de retorno de funcao" , "Falta de teste de retorno pode ocasionar ataques por comprometimento da camada subjacente" , CLASSE_ATAQUE_DIRETO , ASP );

    // Primeira assinatura

    a = AddAssinatura( v );
    AddTokenMask( a , FIMDELINHA , NULL , TIPO_POSITIVO );
    AddTokenMask( a , IDENT      , "if;while;for" , TIPO_NEGATIVO_IDENT );
    AddTokenMask( a , APAR       , NULL , TIPO_POSITIVO );

}
//---------------------------------------------------------------------------
int ChecaAssinaturas( Lexico * lex , int linguagem )
{

    try {

        char buf[4096];
        int sym;
        int nvul = 0;

        int * * stats;
        bool * foiv;
        bool * hasl;

        try {

            stats = (int * *)malloc( nVulnerabilidade * sizeof(int *) );
            memset( stats , 0 , nVulnerabilidade * sizeof(int *) );

            foiv = (bool *)malloc( nVulnerabilidade * sizeof(bool) );
            memset( foiv , 0 , nVulnerabilidade * sizeof(bool) );

            hasl = (bool *)malloc( nVulnerabilidade * sizeof(bool) );
            memset( hasl , 0 , nVulnerabilidade * sizeof(bool) );

            for( int i = 0 ; i < nVulnerabilidade ; i++ ) {

                stats[i] = (int *)malloc( vulnerabilidade[i].nAssinatura * sizeof(int) );
                memset( stats[i] , 0 , vulnerabilidade[i].nAssinatura * sizeof(int) );

                for( int j = 0 ; j < vulnerabilidade[i].nLinguagem ; j++ )
                    if ( vulnerabilidade[i].linguagem[j] == linguagem ) {
                        hasl[i] = true;
                        break;
                    }

            }

            //printf( "Aloquei\n" );

        } catch( ... ) {

            printf( "ERRO FATAL: Aloca��o de Mem�ria\n" );

            return -1;

        }

        while(1) {

            sym = lex->GetSym( buf );
            if ( sym == EOF || sym == NADA )
                break;

            ///printf( "Buf = '%s'\n" , buf );

            for( int i = 0 ; i < nVulnerabilidade ; i++ ) {

                if ( !hasl[i] )
                    continue;

                for( int j = 0 ; j < vulnerabilidade[i].nAssinatura ; j++ ) {

                    int k = stats[i][j];

                    bool tem = false;

                    if ( vulnerabilidade[i].assinatura[j].token[k].tipo == TIPO_POSITIVO ) {

                        for( int l = 0 ; l < vulnerabilidade[i].assinatura[j].token[k].nsym ; l++ ) {

                            if ( sym == vulnerabilidade[i].assinatura[j].token[k].sym[l] ) {

                                if ( !(vulnerabilidade[i].assinatura[j].token[k].ident[l]) || strstr( vulnerabilidade[i].assinatura[j].token[k].ident[l] , buf ) ) {

                                    tem = true;
                                    break;

                                }

                            }

                        }

                    } else if ( vulnerabilidade[i].assinatura[j].token[k].tipo == TIPO_NEGATIVO ) {

                        tem = true;

                        for( int l = 0 ; l < vulnerabilidade[i].assinatura[j].token[k].nsym ; l++ ) {

                            if ( sym == vulnerabilidade[i].assinatura[j].token[k].sym[l] ) {

                                if ( !(vulnerabilidade[i].assinatura[j].token[k].ident[l]) || strstr( vulnerabilidade[i].assinatura[j].token[k].ident[l] , buf ) ) {

                                    tem = false;
                                    break;

                                }

                            }

                        }

                    } else if ( vulnerabilidade[i].assinatura[j].token[k].tipo == TIPO_NEGATIVO_IDENT ) {

                        for( int l = 0 ; l < vulnerabilidade[i].assinatura[j].token[k].nsym ; l++ ) {

                            if ( sym == vulnerabilidade[i].assinatura[j].token[k].sym[l] ) {

                                if ( !(vulnerabilidade[i].assinatura[j].token[k].ident[l]) || !strstr( vulnerabilidade[i].assinatura[j].token[k].ident[l] , buf ) ) {

                                    tem = true;
                                    break;

                                }

                            }

                        }

                    }

                    if ( tem ) {

                        stats[i][j]++;

                        if ( stats[i][j] >= vulnerabilidade[i].assinatura[j].nToken ) {

                            char * arq;
                            int lin, col;

                            //printf( "Achei vul\n" );

                            lex->GetInfo( arq , lin , col );
                            printf( "%s, lin:%d col:%d - %s\n" , arq , lin , col , vulnerabilidade[i].nome );
                            stats[i][j] = 0;
                            foiv[i] = true;

                            if ( fv )
                                fprintf( fv , "%s, %d, %d, %s, %s\n" , arq , lin , col , vulnerabilidade[i].nome , vulnerabilidade[i].descricao );

                            //printf( "Printei vul\n" );

                            nvul++;

                        }

                    } else {

                        stats[i][j] = 0;

                    }

                }

            }

        }

        //printf( "Encerrei\n" );

        try {

            printf( "\n" );
            for( int i = 0 ; i < nVulnerabilidade ; i++ ) {

                if ( foiv[i] )
                    printf( "%s: %s\n" , vulnerabilidade[i].nome , vulnerabilidade[i].descricao );

            }
            printf( "\n" );

        } catch( ... ) {

            printf( "ERRO FATAL: Descri��o de vulnerabilidade\n" );

            return -1;

        }

        //printf( "Botei as vul\n" );

        try {

            for( int i = 0 ; i < nVulnerabilidade ; i++ )
                free( stats[i] );

            free( stats );
            free( foiv );
            free( hasl );

            return nvul;

        } catch( ... ) {

            printf( "ERRO FATAL: Dealoca��o de mem�ria\n" );

            return -1;

        }

        //printf( "Dealoquei\n" );

    } catch( ... ) {

        printf( "ERRO FATAL: N�o Identificado\n" );

        return -1;

    }

}
//---------------------------------------------------------------------------
// Conta linhas l�gicas
#define PALAVRAS_IGNORA "void,static,public,protected,private,extern,new,delete"
void CheckParameters( Lexico * lex , int linguagem , int & Linhas , int & LinhasLogicas )
{

    char buf[8192];
    int sym;

    int numident = 0;
    Linhas = 0;
    LinhasLogicas = 0;

    while(1) {

        sym = lex->GetSym( buf );
        if ( sym == EOF || sym == NADA )
            break;

        if ( sym == IDENT ) {

            if ( !strstr( buf , PALAVRAS_IGNORA ) )
                continue;

            if ( !stricmp( buf , "for" ) )
                LinhasLogicas--;

            numident++;

            if ( numident == 2 ) {

                LinhasLogicas--;

            } else {

                if ( numident > 2 ) {

                    numident = 0;

                }

            }

        } else {

            if ( sym == APAR && numident == 2 ) {

                LinhasLogicas++;

            }

            numident = 0;

        }

        if ( sym == ACHAVES || sym == FIMDELINHA )
            LinhasLogicas++;

    }

    char * arq;
    int col;

    lex->GetInfo( arq , Linhas , col );

}
//---------------------------------------------------------------------------
int TotalArq,TotalLinhas,TotalLinhasLogicas,TotalPossiveisVulnerabilidades;
//---------------------------------------------------------------------------
char * TimeStamp()
{

    static char buf[256];

    SYSTEMTIME st;
    GetLocalTime( &st );
    sprintf( buf , "%02d/%02d/%04d %02d:%02d:%02d:%03d" , st.wDay , st.wMonth , st.wYear , st.wHour , st.wMinute , st.wSecond , st.wMilliseconds );

    return buf;

}
//---------------------------------------------------------------------------
int CheckFileC( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo C '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );

        ChecaAssinaturas( lex , JAVA );

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileCPP( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo C++ '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );

        int l, ll;

        CheckParameters( lex , JAVA , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, C++, %s, %d, %d, %s" , file , sha , l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , JAVA );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFilePascal( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo Pascal '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );

        ChecaAssinaturas( lex , JAVA );

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileJava( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo Java '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );

        int l, ll;

        CheckParameters( lex , JAVA , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, JAVA, %s, %d, %d, %s" , file , sha , l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , JAVA );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}

//---------------------------------------------------------------------------
int CheckFilePhp( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo PHP '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );

        int l, ll;

        CheckParameters( lex , PHP , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, PHP, %s, %d, %d, %s" , file , sha , l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , PHP );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileCSharp( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo CSharp '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        printf( "1\n" );

        Lexico * lex = new LexicalArq( file , h );

        printf( "2\n" );

        int l, ll;

        CheckParameters( lex , JAVA , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, C#, %s, %d, %d, %s" , file , sha , l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , JAVA );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileBasic( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo Basic '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );
        lex->SetBasic( true );

        int l, ll;

        CheckParameters( lex , BAS , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, BASIC, %s, %d, %d, %s" , file , sha, l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , BAS );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileUnknown( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo gen�rico '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex = new LexicalArq( file , h );
        lex->SetBasic( true );

        int l, ll;

        CheckParameters( lex , BAS , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, UNKNOWN, %s, %d, %d, %s" , file , sha, l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        if ( fi )
            fprintf( fi , ", %d\n" , 0 );

        delete lex;

        close( h );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int CheckFileASP( char * file , char * sha )
{

    printf( "\n%s Verificando arquivo ASP '%s'\n\n" , TimeStamp() , file );

    int h = open( file , O_BINARY | O_RDONLY );
    if ( h != -1 ) {

        Lexico * lex;

        try {

            lex = new LexicalArq( file , h );
            lex->SetBasic( true );
            lex->SetASP( true );

        } catch( ... )
        {

            printf( "ERRO FATAL: Criacao do Lexico\n" );

        }

        int l, ll;

        CheckParameters( lex , ASP , l , ll );
        printf( "Numero de linhas: %d\n" , l );
        printf( "Numero de linhas logicas: %d\n\n" , ll );

        if ( fi ) {
            fprintf( fi , "%s, ASP, %s, %d, %d, %s" , file , sha, l , ll , TimeStamp() );
            fflush( fi );
        }

        TotalLinhas += l;
        TotalLinhasLogicas += ll;

        lex->Rewind();

        int v = ChecaAssinaturas( lex , ASP );

        if ( fi )
            fprintf( fi , ", %d\n" , v );

        TotalPossiveisVulnerabilidades += v;

        try {

            delete lex;

        } catch( ... )
        {

            printf( "ERRO FATAL: Remocao do Lexico\n" );

        }


        close( h );

    } else {

        int e = GetLastError();
        printf( "Falhei em abrir = %d\n" , e );

    }

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
int get6bits( int n , unsigned char * b , unsigned int len )
{

    int pos_a = n / 8;
    int mod_a = n % 8;

    unsigned int mask = (unsigned int)0x003F << mod_a;
    unsigned int m1 = (mask & 0xFF00) >> 8;
    unsigned int m2 = (mask & 0x00FF);

    if ( pos_a >= len ) return 0;

    unsigned int v1 = (unsigned int)(b[pos_a] & (unsigned char)m2);

    if ( pos_a+1 < len )
    {

        v1 = v1 | ((unsigned int)(b[pos_a+1] & (unsigned char)m1) << 8);

    }

    v1 >>= mod_a;

    return (int)v1;

}
//---------------------------------------------------------------------------
char * Expand( unsigned char * data , int len )
{

    char * hex = new char [ len * 2 + 1 ];
    char buf[3];

    for( int i = 0 ; i < len ; i++ ) {

        sprintf( buf , "%02X" , (unsigned int)(data[i]) );
        hex[i*2+0] = buf[0];
        hex[i*2+1] = buf[1];

    }

    hex[len*2] = 0;

    return hex;

}
//---------------------------------------------------------------------------
char * ConvertCharToBase64( unsigned char * data , int len )
{

    char * base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int nbits = len * 8;

    int queb = nbits % 6;
    int size = nbits / 6;

    if ( queb == 2 ) size += 1;
    if ( queb == 4 ) size += 2;

    char * res = new char [ size+1 ];
    int conta = 0;

    for( int i = 0 ; i < nbits ; i += 6 )
    {

        res[conta++] = base64[ get6bits( i , data , len ) ];

    }

    if ( queb == 2 ) { res[size-2] = '-'; res[size-3] = '-'; }
    if ( queb == 4 ) { res[size-2] = '-'; }
    res[size-1] = 0;

    return res;

}
//---------------------------------------------------------------------------
char * CalcHash( char * file )
{

    unsigned char * byte = NULL;
    unsigned long size = 0;

    int h = open( file , O_RDONLY | O_BINARY );
    if ( h != -1 ) {

        size = lseek( h , 0L , SEEK_END );

        try {

            byte = new unsigned char [ size ];

            lseek( h , 0L , SEEK_SET );

            read( h , byte , size );

            unsigned char md[20];
            memset( md , 0 , 20 );

            unsigned char * res = SHA1( byte , size , md );

            delete byte;
            close( h );

            return Expand( res , 20 );

        } catch( ... ) {

            return "Sem mem�ria para HASH";

        }

    }

    return "-";

}
//---------------------------------------------------------------------------
int CheckFile( char * file )
{

    if ( !file )
        return iErro = ERRO_ARGUMENTO_INVALIDO;

    char * ext = strrchr( file , '.' );

    TotalArq++;

    char * sha = CalcHash( file );

    if ( iLinguagem == CHECK ) {

        if ( !stricmp( ext , ".c" ) )
            return CheckFileC( file , sha );

        if ( !stricmp( ext , ".h" ) )
            return CheckFileCPP( file , sha );

        if ( !stricmp( ext , ".cpp" ) )
            return CheckFileCPP( file , sha );

        if ( !stricmp( ext , ".cs" ) )
            return CheckFileCSharp( file , sha );

        if ( !stricmp( ext , ".java" ) )
            return CheckFileJava( file , sha );

        if ( !stricmp( ext , ".pas" ) )
            return CheckFilePascal( file , sha );

        if ( !stricmp( ext , ".php" ) )
            return CheckFilePhp( file , sha );

        if ( !stricmp( ext , ".bas" ) )
            return CheckFileBasic( file , sha );

        if ( !stricmp( ext , ".vb" ) )
            return CheckFileBasic( file , sha );

        if ( !stricmp( ext , ".vbs" ) )
            return CheckFileBasic( file , sha );

        if ( !stricmp( ext , ".cls" ) )
            return CheckFileBasic( file , sha );

        if ( !stricmp( ext , ".asp" ) )
            return CheckFileASP( file , sha );

        if ( !stricmp( ext , ".aspx" ) )
            return CheckFileASP( file , sha );

        return CheckFileUnknown( file , sha );

    }

    switch( iLinguagem ) {

        case C :
            return CheckFileC( file , sha );

        case CPP :
            return CheckFileCPP( file , sha );

        case JAVA :
            return CheckFileJava( file , sha );

        case PHP :
            return CheckFilePhp( file , sha );

        case PAS :
            return CheckFilePascal( file , sha );

        case BAS :
            return CheckFileBasic( file , sha );

        case ASP :
            return CheckFileASP( file , sha );

        case CSHARP :
            return CheckFileCSharp( file , sha );

        default :
            return iErro = ERRO_PARAMETRO_INVALIDO;

    }

}
//---------------------------------------------------------------------------
// Navigate (parte recursiva)
int NavigateUm( char * dir , char * arq )
{

   if ( !dir || !arq )
        return SUCESSO;

    char path[4096];

    strncpy( path , dir , 4096 );
    if ( path[strlen(path)-1] != '\\' )
        strcat( path , "\\" );

    char * pto = path + strlen(path);

    WIN32_FIND_DATA FFData;

    // Primeiro os diret�rios

    strcpy( pto , "*.*" );
    HANDLE hb = FindFirstFile( path , &FFData );
    if ( hb != INVALID_HANDLE_VALUE ) {

        do {

            if ( FFData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {

                if ( FFData.cFileName[0] != '.' ) {

                    strcpy( pto , FFData.cFileName );
                    NavigateUm( path , arq );
                    strcpy( pto , "*.*" );

                }

            }

        } while( FindNextFile( hb , &FFData ) );

        FindClose( hb );

    }

    // Primeiro os diret�rios

    strcpy( pto , arq );
    hb = FindFirstFile( path , &FFData );
    if ( hb != INVALID_HANDLE_VALUE ) {

        do {

            if ( !(FFData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ) {

                if ( FFData.cFileName[0] != '.' ) {

                    strcpy( pto , FFData.cFileName );
                    CheckFile( path );
                    strcpy( pto , arq );

                }

            }

        } while( FindNextFile( hb , &FFData ) );

        FindClose( hb );

    }

    *pto = 0;

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
// Navigate Inicio
int Navigate( char * dir , char * arq )
{

    return NavigateUm( dir , arq );

}
//---------------------------------------------------------------------------
// Escolhe linguagem
int AchaLinguagem( char * opt )
{

    iLinguagem = CHECK;

    if ( !stricmp( opt , "C" ) )        iLinguagem = C;
    if ( !stricmp( opt , "CPP" ) )      iLinguagem = CPP;
    if ( !stricmp( opt , "C++" ) )      iLinguagem = CPP;
    if ( !stricmp( opt , "JAVA" ) )     iLinguagem = JAVA;
    if ( !stricmp( opt , "BASIC" ) )    iLinguagem = BAS;
    if ( !stricmp( opt , "BAS" ) )      iLinguagem = BAS;
    if ( !stricmp( opt , "ASP" ) )      iLinguagem = ASP;
    if ( !stricmp( opt , "PHP" ) )      iLinguagem = PHP;
    if ( !stricmp( opt , "PASCAL" ) )   iLinguagem = PAS;
    if ( !stricmp( opt , "DELPHI" ) )   iLinguagem = PAS;
    if ( !stricmp( opt , "PAS" ) )      iLinguagem = PAS;
    if ( !stricmp( opt , "C#" ) )       iLinguagem = CSHARP;
    if ( !stricmp( opt , "CS" ) )       iLinguagem = CSHARP;
    if ( !stricmp( opt , "CSHARP" ) )   iLinguagem = CSHARP;

    return iErro = SUCESSO;

}
//---------------------------------------------------------------------------
// Ponto de entrada
int main( int argc , char * argv[] )
{

    printf( "SRCI - Source Inspector\n" );
    printf( "(C) 2003,2004,2005 Sereno Sistemas Ltda\n" );
    printf( "Patente no INPI 00069204\n\n" );

    if ( argc < 3 || argc > 4 ) {

        printf( "USO:   SRCI diretorio arquivos [linguagem]\n\n" );
        printf( "ONDE:  diretorio e o diretorio raiz dos fontes\n" );
        printf( "       arquivos e a mascara dos arquivos a inspecionar (*.java, p.ex.)\n" );
        printf( "       linguagem (opcional) e uma das seguintes:\n" );
        printf( "            C\n" );
        printf( "            C++ (Inclui Builder)\n" );
        printf( "            Pascal (Inclui Delphi)\n" );
        printf( "            Basic(Inclui VisualBasic)\n" );
        printf( "            ASP(Inclui aspx)\n" );
        printf( "            C#\n" );
        printf( "            PHP\n" );
        printf( "            Java\n\n" );

        exit(0);

    }

    // Define a linguagem

    iLinguagem = CHECK;

    if ( argc > 3 )
        AchaLinguagem( argv[3] );

    fv = fopen( "outvul.txt" , "w" );
    if ( fv )
        fprintf( fv , "Arquivo, Linha, Coluna, Vulnerabilidade, Descricao\n" );

    fi = fopen( "outinf.txt" , "w" );
    if ( fi )
        fprintf( fi , "Arquivo, Linguagem, HASH SHA-1, Linhas, Linhas logicas, Analisado em, Possiveis vulnerabilidades\n" );

    // Adivinha!

    MontaTabelaVulnerabilidade();

    TotalArq = 0;
    TotalLinhas = 0;
    TotalLinhasLogicas = 0;
    TotalPossiveisVulnerabilidades = 0;

    // Busca os diret�rios

    Navigate( argv[1] , argv[2] );

    printf( "\n%s Encerrando execucao\n\n" , TimeStamp() );
    printf( "Numero total de arquivos inspecionadas: %d\n" , TotalArq );
    printf( "Numero total de linhas inspecionadas: %d\n" , TotalLinhas );
    printf( "Numero total de linhas logicas inspecionadas: %d\n\n" , TotalLinhasLogicas );
    printf( "Numero total de possiveis vulnerabilidades encontradas: %d\n\n" , TotalPossiveisVulnerabilidades );

    if ( fi )
        fclose( fi );

    if ( fv )
        fclose( fv );

    return SUCESSO;

}
//---------------------------------------------------------------------------
