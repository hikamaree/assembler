%option noyywrap
%option yylineno

%{
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "assembler.h"
#include "assembler.tab.h"
%}

%x COMMENT

%%

"#".*                       ;
[ \t\r\n]+                  ;

"["             			{ return LBRACKET; }
"]"             			{ return RBRACKET; }
"+"             			{ return PLUS; }
"-"             			{ return MINUS; }
","                         { return COMMA; }
"$"                         { return DOLLAR; }

"halt"                      { return HALT; }
"int"                       { return INT; }
"iret"                      { return IRET; }
"ret"                       { return RET; }
"jmp"                       { return JMP; }
"call"                      { return CALL; }
"beq"                       { return BEQ; }
"bne"                       { return BNE; }
"bgt"                       { return BGT; }
"push"                      { return PUSH; }
"pop"                       { return POP; }
"xchg"                      { return XCHG; }
"add"                       { return ADD; }
"sub"                       { return SUB; }
"mul"                       { return MUL; }
"div"                       { return DIV; }
"not"                       { return NOT; }
"and"                       { return AND; }
"or"                        { return OR; }
"xor"                       { return XOR; }
"shl"                       { return SHL; }
"shr"                       { return SHR; }
"ld"                        { return LD; }
"st"                        { return ST; }
"csrrd"                     { return CSRRD; }
"csrwr"                     { return CSRWR; }

".section"                  { return SECTION; }
".word"                     { return WORD; }
".skip"                     { return SKIP; }
".global"                   { return GLOBAL; }
".extern"                   { return EXTERN; }
".equ"                   	{ return EQU; }
".end"                      { return END; }
".ascii"                    { return ASCII; }

%r(1[0-5]|[0-9])|%sp|%pc {
	g_current_yytext = yytext;
    yylval.str = strdup(yytext + 1);
    return REGISTER;
}

%status|%handler|%cause|%csr[0-2] {
	g_current_yytext = yytext;
	yylval.str = strdup(yytext + 1);
    return CSR;
}

0[xX][0-9a-fA-F]+ {
	g_current_yytext = yytext;
    yylval.ival = (int)strtol(yytext, NULL, 0);
    return NUMBER;
}

[0-9]+ {
	g_current_yytext = yytext;
    yylval.ival = atoi(yytext);
    return NUMBER;
}

[a-zA-Z_][a-zA-Z0-9_]*: {
	g_current_yytext = yytext;
	yytext[yyleng - 1] = '\0';
    yylval.str = strdup(yytext);
    return LABEL;
}

[a-zA-Z_][a-zA-Z0-9_]* {
	g_current_yytext = yytext;
	yylval.str = strdup(yytext);
	return IDENTIFIER;
}

\"([^\"\n]*)\" { 
	g_current_yytext = yytext;
	yylval.str = strdup(yytext + 1);
	yylval.str[strlen(yylval.str) - 1] = '\0';
	return STRING;
}

. {
	unsigned char ch = yytext[0];
	fprintf(stderr, "Unknown character: '%s' (ASCII: %d, Hex: 0x%02X) at line %d\n",
			isprint(ch) ? yytext : "<non-printable>", ch, ch, yylineno);
	exit(1);
}

%%
