%{
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "string_list.h"

extern int yylineno;

extern int parse_register(const char* str);
extern int parse_csr(const char* str);

extern void assembler_handle_label(const char* label);
extern void assembler_handle_section(const char* section_name);
extern void assembler_handle_word(const StringList* words);
extern void assembler_handle_skip(int size);
extern void assembler_handle_global(const StringList* symbols);
extern void assembler_handle_extern(const StringList* symbols);
extern void assembler_handle_end();
extern void assembler_handle_ascii(const char* str);

extern void assembler_handle_halt(void);
extern void assembler_handle_int(void);
extern void assembler_handle_iret(void);
extern void assembler_handle_ret(void);

extern void assembler_handle_call(const Operand* op);
extern void assembler_handle_jmp(const Operand* op);
extern void assembler_handle_push(const Operand* op);
extern void assembler_handle_pop(const Operand* op);
extern void assembler_handle_not(const Operand* op);

extern void assembler_handle_xchg(const Operand* op1, const Operand* op2);
extern void assembler_handle_add(const Operand* op1, const Operand* op2);
extern void assembler_handle_sub(const Operand* op1, const Operand* op2);
extern void assembler_handle_mul(const Operand* op1, const Operand* op2);
extern void assembler_handle_div(const Operand* op1, const Operand* op2);
extern void assembler_handle_and(const Operand* op1, const Operand* op2);
extern void assembler_handle_or(const Operand* op1, const Operand* op2);
extern void assembler_handle_xor(const Operand* op1, const Operand* op2);
extern void assembler_handle_shl(const Operand* op1, const Operand* op2);
extern void assembler_handle_shr(const Operand* op1, const Operand* op2);
extern void assembler_handle_ld(const Operand* dst, const Operand* src);
extern void assembler_handle_st(const Operand* src, const Operand* dst);
extern void assembler_handle_csrrd(const Operand* dst, const Operand* src);
extern void assembler_handle_csrwr(const Operand* src, const Operand* dst);

extern void assembler_handle_beq(const Operand* op1, const Operand* op2, const Operand* target);
extern void assembler_handle_bne(const Operand* op1, const Operand* op2, const Operand* target);
extern void assembler_handle_bgt(const Operand* op1, const Operand* op2, const Operand* target);

void yyerror(const char *s);
int yylex(void);
%}

%union {
    int ival;
    char* str;
    struct Operand* operand_ptr;
	StringList* str_list;
}

%token HALT INT IRET CALL RET JMP
%token BEQ BNE BGT
%token PUSH POP XCHG
%token ADD SUB MUL DIV NOT AND OR XOR SHL SHR
%token LD ST CSRWR CSRRD


%token SECTION WORD SKIP GLOBAL EXTERN END ASCII

%token<str> REGISTER CSR IDENTIFIER
%token<ival> NUMBER DATANUM
%token<str> LITERAL
%token<str> LABEL STRING
%token COMMA LBRACKET RBRACKET PLUS

%type<operand_ptr> operand

%type <str_list> symbols words
%type <void> instruction line label_definition directive program lines

%%

program:
    lines
;

lines:
    /* empty */ { }
    | lines line { }
;

line:
    label_definition                { /* samo labela */ }
  | instruction                     { /* samo instrukcija */ }
  | directive                       { /* samo direktiva */ }
  | label_definition instruction    { /* labela + instrukcija u istoj liniji */ }
  | label_definition directive      { /* labela + direktiva u istoj liniji */ }
;

label_definition:
    LABEL { assembler_handle_label($1); free($1); }
;

instruction:
      HALT                  { assembler_handle_halt(); }
    | INT                   { assembler_handle_int(); }
    | IRET                  { assembler_handle_iret(); }
    | CALL operand          { assembler_handle_call($2); free($2); }
    | RET                   { assembler_handle_ret(); }
    | JMP operand           { assembler_handle_jmp($2); free($2); }
    | BEQ operand COMMA operand COMMA operand {
          assembler_handle_beq($2, $4, $6);
          free($2); free($4); free($6);
      }
    | BNE operand COMMA operand COMMA operand {
          assembler_handle_bne($2, $4, $6);
          free($2); free($4); free($6);
      }
    | BGT operand COMMA operand COMMA operand {
          assembler_handle_bgt($2, $4, $6);
          free($2); free($4); free($6);
      }
    | PUSH operand {
          assembler_handle_push($2);
          free($2);
      }
    | POP operand {
          assembler_handle_pop($2);
          free($2);
      }
    | XCHG operand COMMA operand {
          assembler_handle_xchg($2, $4);
          free($2); free($4);
      }
    | ADD operand COMMA operand {
          assembler_handle_add($2, $4);
          free($2); free($4);
      }
    | SUB operand COMMA operand {
          assembler_handle_sub($2, $4);
          free($2); free($4);
      }
    | MUL operand COMMA operand {
          assembler_handle_mul($2, $4);
          free($2); free($4);
      }
    | DIV operand COMMA operand {
          assembler_handle_div($2, $4);
          free($2); free($4);
      }
    | NOT operand {
          assembler_handle_not($2);
          free($2);
      }
    | AND operand COMMA operand {
          assembler_handle_and($2, $4);
          free($2); free($4);
      }
    | OR operand COMMA operand {
          assembler_handle_or($2, $4);
          free($2); free($4);
      }
    | XOR operand COMMA operand {
          assembler_handle_xor($2, $4);
          free($2); free($4);
      }
    | SHL operand COMMA operand {
          assembler_handle_shl($2, $4);
          free($2); free($4);
      }
    | SHR operand COMMA operand {
          assembler_handle_shr($2, $4);
          free($2); free($4);
      }
    | LD operand COMMA operand {
          assembler_handle_ld($2, $4);
          free($2); free($4);
      }
    | ST operand COMMA operand {
          assembler_handle_st($2, $4);
          free($2); free($4);
      }
    | CSRRD operand COMMA operand {
          assembler_handle_csrrd($2, $4);
          free($2); free($4);
      }
    | CSRWR operand COMMA operand {
          assembler_handle_csrwr($2, $4);
          free($2); free($4);
      }
;

operand:
      REGISTER {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_REG;
        $$->reg = parse_register($1);
        free($1);
      }
    | CSR {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_CSR;
        $$->csr = parse_csr($1);
        free($1);
      }
    | NUMBER {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_NUMBER;
        $$->literal = $1;
      }
    | DATANUM {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_ADDR;
        $$->literal = $1;
      }
    | LITERAL {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_LITERAL;
        $$->literal = 0;
        $$->symbol = $1;
      }
    | IDENTIFIER {
        $$ = malloc(sizeof(Operand));
        $$->type = OPERAND_SYMBOL;
        $$->literal = 0;
        $$->symbol = $1;
      }
    | LBRACKET REGISTER RBRACKET {
    	$$ = malloc(sizeof(Operand));
    	$$->type = OPERAND_MEM;
    	$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = 0x0;
    	$$->mem.offset = 0;
    	$$->mem.offset_symbol = NULL;
		free($2);
      }
    | LBRACKET REGISTER PLUS DATANUM RBRACKET {
		$$ = malloc(sizeof(Operand));
		$$->type = OPERAND_MEM;
		$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = 0x0;
		$$->mem.offset = $4;
		$$->mem.offset_symbol = NULL;
		free($2);
      }
    | LBRACKET REGISTER PLUS IDENTIFIER RBRACKET {
		$$ = malloc(sizeof(Operand));
		$$->type = OPERAND_MEM;
		$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = 0x0;
		$$->mem.offset = 0;
		$$->mem.offset_symbol = $4;
		free($2);
      }
	| LBRACKET REGISTER PLUS REGISTER RBRACKET {
    	$$ = malloc(sizeof(Operand));
    	$$->type = OPERAND_MEM;
    	$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = parse_register($4);
    	$$->mem.offset = 0;
    	$$->mem.offset_symbol = NULL;
    	free($2);
    	free($4);
	}
	| LBRACKET REGISTER PLUS REGISTER PLUS DATANUM RBRACKET {
    	$$ = malloc(sizeof(Operand));
    	$$->type = OPERAND_MEM;
    	$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = parse_register($4);
    	$$->mem.offset = $6;
    	$$->mem.offset_symbol = NULL;
    	free($2);
    	free($4);
	}
	| LBRACKET REGISTER PLUS REGISTER PLUS IDENTIFIER RBRACKET {
    	$$ = malloc(sizeof(Operand));
    	$$->type = OPERAND_MEM;
    	$$->mem.base_reg = parse_register($2);
    	$$->mem.index_reg = parse_register($4);
    	$$->mem.offset = 0;
    	$$->mem.offset_symbol = $6;
    	free($2);
    	free($4);
	}
;

directive:
    SECTION IDENTIFIER { assembler_handle_section($2); free($2); }
    | WORD words { assembler_handle_word($2); free_string_list($2); }
    | SKIP DATANUM { assembler_handle_skip($2); }
    | GLOBAL symbols { assembler_handle_global($2); free_string_list($2); }
    | EXTERN symbols { assembler_handle_extern($2); free_string_list($2); }
    | END { assembler_handle_end(); }
  	| ASCII STRING { assembler_handle_ascii($2); }
;

symbols:
    IDENTIFIER { $$ = create_string_list(); string_list_push_back($$, $1); free($1); }
    | symbols COMMA IDENTIFIER { string_list_push_back($1, $3); free($3); $$ = $1; }
;

words:
    DATANUM {
        $$ = create_string_list();
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", $1);
        string_list_push_back($$, buf);
    }
    | words COMMA DATANUM {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", $3);
        string_list_push_back($1, buf);
        $$ = $1;
    }
;

%%

void yyerror(const char *s) {
    fprintf(stderr, "Parser error: %s at line %d near token '%s'\n", s, yylineno, g_current_yytext ? g_current_yytext : "(unknown)");
}

