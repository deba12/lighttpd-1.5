%token_prefix TK_
%token_type {buffer *}
%extra_argument {config_t *ctx}
%name configparser

%include {
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "configfile.h"
#include "buffer.h"
#include "array.h"

static void configparser_push(config_t *ctx, data_config *dc, int isnew) {
  if (isnew) {
    dc->context_ndx = ctx->all_configs->used;
    assert(dc->context_ndx > ctx->current->context_ndx);
    array_insert_unique(ctx->all_configs, (data_unset *)dc);
    dc->parent = ctx->current;
  }
  array_insert_unique(ctx->configs_stack, (data_unset *)ctx->current);
  ctx->current = dc;
}

static data_config *configparser_pop(config_t *ctx) {
  data_config *old = ctx->current;
  ctx->current = (data_config *) array_pop(ctx->configs_stack);
  return old;
}

data_unset *configparser_get_variable(config_t *ctx, buffer *key) {
  data_unset *ds, *result;
  data_config *dc;

  result = NULL;
#if 0
  fprintf(stderr, "get var %s\n", key->ptr);
#endif
  for (dc = ctx->current; dc && !result; dc = dc->parent) {
#if 0
    fprintf(stderr, "get var on block: %s\n", dc->key->ptr);
#endif
    ds = array_get_element(dc->value, key->ptr);
    if (NULL != ds) {
      result = ds;
      break;
    }
  }
  if (NULL == result) {
    fprintf(stderr, "Undefined config variable: %s\n", key->ptr);
    ctx->ok = 0;
  }
  return result;
}

/* op1 is to be eat/return by this function, op1->key is not cared
   op2 is left untouch, unreferenced
 */
data_unset *configparser_merge_data(config_t *ctx, data_unset *op1, const data_unset *op2) {
  /* type mismatch */
  if (op1->type != op2->type) {
    if (op1->type == TYPE_STRING && op2->type == TYPE_INTEGER) {
      data_string *ds = (data_string *)op1;
      buffer_append_long(ds->value, ((data_integer*)op2)->value);
      return op1;
    }
    else if (op1->type == TYPE_INTEGER && op2->type == TYPE_STRING) {
      data_string *ds = data_string_init();
      buffer_append_long(ds->value, ((data_integer*)op1)->value);
      buffer_append_string_buffer(ds->value, ((data_string*)op2)->value);
      op1->free(op1);
      return (data_unset *)ds;
    }
    else {
      fprintf(stderr, "data type mismatch, cannot be merge\n");
      ctx->ok = 0;
      op1->free(op1);
      return NULL;
    }
  }

  switch (op1->type) {
    case TYPE_STRING:
      buffer_append_string_buffer(((data_string *)op1)->value, ((data_string *)op2)->value);
      break;
    case TYPE_INTEGER:
      ((data_integer *)op1)->value += ((data_integer *)op2)->value;
      break;
    case TYPE_ARRAY: {
      array *dst = ((data_array *)op1)->value;
      array *src = ((data_array *)op2)->value;
      data_unset *du;
      size_t i;

      for (i = 0; i < src->used; i ++) {
        du = (data_unset *)src->data[i];
        if (du) {
          array_insert_unique(dst, du->copy(du));
        }
      }
      break;
    default:
      assert(0);
      break;
    }
  }
  return op1;
}

}

%parse_failure {
  ctx->ok = 0;
}

input ::= metalines.
metalines ::= metalines metaline.
metalines ::= .
metaline ::= varline.
metaline ::= condlines EOL.
metaline ::= include.
metaline ::= EOL.

%type value {data_unset *}
%type expression {data_unset *}
%type context_rvalue {data_unset *}
%type aelement {data_unset *}
%type aelements {array *}
%type array {array *}
%type condline {data_config *}
%type condlines {data_config *}
%type cond {config_cond_t }
%token_destructor { buffer_free($$); }

varline ::= key(A) ASSIGN expression(B). {
  buffer_copy_string_buffer(B->key, A);
  if (NULL == array_get_element(ctx->current->value, B->key->ptr)) {
    array_insert_unique(ctx->current->value, B);
  } else {
    fprintf(stderr, "Duplicate config variable in conditional 1 %s: %s\n", 
            ctx->current->key->ptr, B->key->ptr);
    ctx->ok = 0;
    B->free(B);
  }
  buffer_free(A);
}

varline ::= key(A) APPEND expression(B). {
  array *vars = ctx->current->value;
  data_unset *du;

  if (NULL == (du = configparser_get_variable(ctx, A))) {
    fprintf(stderr, "Undefined config variable in conditional 1 %s: %s\n", 
            ctx->current->key->ptr, A->ptr);
    ctx->ok = 0;
  } else if (NULL != (du = array_get_element(vars, A->ptr))) {
    /* exists in current block */
    du = configparser_merge_data(ctx, du, B);
    buffer_copy_string_buffer(du->key, A);
    array_replace(vars, du);
  } else {
    du = configparser_merge_data(ctx, du->copy(du), B);
    buffer_copy_string_buffer(du->key, A);
    array_insert_unique(ctx->current->value, du);
  }
  buffer_free(A);
  A = NULL;
  B->free(B);
  B = NULL;
}

key(A) ::= LKEY(B). {
  if (strchr(B->ptr, '.') == NULL) {
    A = buffer_init_string("var.");
    buffer_append_string_buffer(A, B);
  }
  else {
    A = B;
    B = NULL;
  }
}

expression(A) ::= expression(B) PLUS value(C). {
  A = configparser_merge_data(ctx, B, C);
  B = NULL;
  C->free(C);
  C = NULL;
}

expression(A) ::= value(B). {
  A = B;
  B = NULL;
}

value(A) ::= key(B). {
  A = configparser_get_variable(ctx, B);
  if (!A) {
    /* make a dummy so it won't crash */
    A = (data_unset *)data_string_init();
  }
  buffer_free(B);
  B = NULL;
}

value(A) ::= STRING(B). {
  A = (data_unset *)data_string_init();
  buffer_copy_string_buffer(((data_string *)(A))->value, B);
  buffer_free(B);
}

value(A) ::= INTEGER(B). {
  A = (data_unset *)data_integer_init();
  ((data_integer *)(A))->value = strtol(B->ptr, NULL, 10);
  buffer_free(B);
}
value(A) ::= array(B). {
  A = (data_unset *)data_array_init();
  array_free(((data_array *)(A))->value);
  ((data_array *)(A))->value = B;
}
array(A) ::= LPARAN aelements(B) RPARAN. {
  A = B;
  B = NULL;
}

aelements(A) ::= aelements(C) COMMA aelement(B). {
  if (buffer_is_empty(B->key) ||
      NULL == array_get_element(C, B->key->ptr)) {
    array_insert_unique(C, B);
  } else {
    fprintf(stderr, "Duplicate array-key: %s\n", 
            B->key->ptr);
    B->free(B);
    ctx->ok = 0;
  }
  
  A = C;
}

aelements(A) ::= aelements(C) COMMA. {
  A = C;
}

aelements(A) ::= aelement(B). {
  A = array_init();
  array_insert_unique(A, B);
}

aelement(A) ::= expression(B). {
  A = B;
  B = NULL;
}
aelement(A) ::= STRING(B) ARRAY_ASSIGN expression(C). {
  buffer_copy_string_buffer(C->key, B);
  buffer_free(B);
  
  A = C;
  C = NULL;
}

eols ::= EOL.
eols ::= .

condlines(A) ::= condlines(B) eols ELSE condline(C). {
  assert(B->context_ndx < C->context_ndx);
  C->prev = B;
  B->next = C;
  A = C;
  B = NULL;
  C = NULL;
}

condlines(A) ::= condline(B). {
  A = B;
  B = NULL;
}

condline(A) ::= context LCURLY metalines RCURLY. {
  data_config *cur;
  
  cur = ctx->current;
  configparser_pop(ctx);

  assert(cur && ctx->current);

  A = cur;
}

context ::= DOLLAR SRVVARNAME(B) LBRACKET STRING(C) RBRACKET cond(E) expression(D). {
  data_config *dc;
  buffer *b, *rvalue;

  if (ctx->ok && D->type != TYPE_STRING) {
    fprintf(stderr, "rvalue must be string");
    ctx->ok = 0;
  }

  b = buffer_init();
  buffer_copy_string_buffer(b, ctx->current->key);
  buffer_append_string(b, "/");
  buffer_append_string_buffer(b, B);
  buffer_append_string_buffer(b, C);
  switch(E) {
  case CONFIG_COND_NE:
    buffer_append_string_len(b, CONST_STR_LEN("!="));
    break;
  case CONFIG_COND_EQ:
    buffer_append_string_len(b, CONST_STR_LEN("=="));
    break;
  case CONFIG_COND_NOMATCH:
    buffer_append_string_len(b, CONST_STR_LEN("!~"));
    break;
  case CONFIG_COND_MATCH:
    buffer_append_string_len(b, CONST_STR_LEN("=~"));
    break;
  default:
    buffer_append_string_len(b, CONST_STR_LEN("??"));
    break;
  }
  rvalue = ((data_string*)D)->value;
  buffer_append_string_buffer(b, rvalue);
  
  if (NULL != (dc = (data_config *)array_get_element(ctx->all_configs, b->ptr))) {
    configparser_push(ctx, dc, 0);
  } else {
    dc = data_config_init();
    
    buffer_copy_string_buffer(dc->key, b);
    buffer_copy_string_buffer(dc->comp_key, B);
    buffer_append_string_buffer(dc->comp_key, C);
    dc->cond = E;
    
    switch(E) {
    case CONFIG_COND_NE:
    case CONFIG_COND_EQ:
      dc->string = buffer_init_buffer(rvalue);
      break;
    case CONFIG_COND_NOMATCH:
    case CONFIG_COND_MATCH: {
#ifdef HAVE_PCRE_H
      const char *errptr;
      int erroff;
      
      if (NULL == (dc->regex = 
          pcre_compile(rvalue->ptr, 0, &errptr, &erroff, NULL))) {
        dc->string = buffer_init_string(errptr);
        dc->cond = CONFIG_COND_UNSET;

        fprintf(stderr, "parsing regex failed: %s -> %s at offset %d\n", 
            rvalue->ptr, errptr, erroff);

        ctx->ok = 0;
      } else if (NULL == (dc->regex_study =
          pcre_study(dc->regex, 0, &errptr)) &&  
                 errptr != NULL) {
        fprintf(stderr, "studying regex failed: %s -> %s\n", 
            rvalue->ptr, errptr);
        ctx->ok = 0;
      } else {
        dc->string = buffer_init_buffer(rvalue);
      }
#else
      fprintf(stderr, "regex conditionals are not allowed as pcre-support" \
                      "is missing: $%s[%s]\n", 
                      B->ptr, C->ptr);
      ctx->ok = 0;
#endif
      break;
    }

    default:
      fprintf(stderr, "unknown condition for $%s[%s]\n", 
                      B->ptr, C->ptr);
      ctx->ok = 0;
      break;
    }
    
    configparser_push(ctx, dc, 1);
  }

  buffer_free(b);
  D->free(D);
  D = NULL;
}
cond(A) ::= EQ. {
  A = CONFIG_COND_EQ;
}
cond(A) ::= MATCH. {
  A = CONFIG_COND_MATCH;
}
cond(A) ::= NE. {
  A = CONFIG_COND_NE;
}
cond(A) ::= NOMATCH. {
  A = CONFIG_COND_NOMATCH;
}

include ::= INCLUDE expression(A). {
  if (ctx->ok) {
    if (A->type != TYPE_STRING) {
      fprintf(stderr, "file must be string");
      ctx->ok = 0;
    }
    else {
      buffer *file = ((data_string*)A)->value;
      if (0 != config_parse_file(ctx->srv, ctx, file->ptr)) {
        ctx->ok = 0;
      }
    }
    A->free(A);
  }
  A = NULL;
}
