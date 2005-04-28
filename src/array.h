#ifndef ARRAY_H
#define ARRAY_H

#include <stdlib.h>
#include "config.h"
#ifdef HAVE_PCRE_H
# include <pcre.h>
#endif
#include "buffer.h"

#define DATA_IS_STRING(x) (x->type == TYPE_STRING)

typedef enum { TYPE_UNSET, TYPE_STRING, TYPE_COUNT, TYPE_ARRAY, TYPE_INTEGER, TYPE_FASTCGI, TYPE_CONFIG } data_type_t;
#define DATA_UNSET \
	data_type_t type; \
	buffer *key; \
	struct data_unset *(*copy)(struct data_unset *src); \
	void (* free)(struct data_unset *p); \
	void (* reset)(struct data_unset *p); \
	int (*insert_dup)(struct data_unset *dst, struct data_unset *src); \
	void (*print)(struct data_unset *p, int depth)

typedef struct data_unset {
	DATA_UNSET;
} data_unset;

typedef struct {
	data_unset  **data;
	
	size_t *sorted;
	
	size_t used;
	size_t size;
	
	size_t unique_ndx;
	
	size_t next_power_of_2;
} array;

typedef struct {
	DATA_UNSET;
	
	int count;
} data_count;

data_count *data_count_init(void);

typedef struct {
	DATA_UNSET;
	
	buffer *value;
} data_string;

data_string *data_string_init(void);
data_string *data_response_init(void);

typedef struct {
	DATA_UNSET;
	
	array *value;
} data_array;

data_array *data_array_init(void);

typedef enum { CONFIG_COND_UNSET, CONFIG_COND_EQ, CONFIG_COND_MATCH, CONFIG_COND_NE, CONFIG_COND_NOMATCH } config_cond_t;
typedef enum { COND_RESULT_FALSE, COND_RESULT_TRUE, COND_RESULT_UNSET } cond_result_t;

/* $HTTP["host"] ==    "incremental.home.kneschke.de" { ... } 
 * comp_key      cond  string/regex
 */

typedef struct _data_config data_config;
struct _data_config {
	DATA_UNSET;
	
	array *value;
	
	buffer *comp_key;
	
	config_cond_t cond;
	int context_ndx; /* more or less like an id */
	array *childs;
	/* nested */
	data_config *parent;
	/* for chaining only */
	data_config *prev;
	data_config *next;
	
	buffer *string;
#ifdef HAVE_PCRE_H
	pcre   *regex;
	pcre_extra *regex_study;
#endif
};

data_config *data_config_init(void);

typedef struct {
	DATA_UNSET;
	
	int value;
} data_integer;

data_integer *data_integer_init(void);

typedef struct {
	DATA_UNSET;

	buffer *host;
	
	unsigned short port;
	int usage;

	time_t disable_ts;
	
} data_fastcgi;

data_fastcgi *data_fastcgi_init(void);

array *array_init(void);
array *array_init_array(array *a);
void array_free(array *a);
void array_reset(array *a);
int array_insert_unique(array *a, data_unset *str);
data_unset *array_pop(array *a);
int array_print(array *a, int depth);
data_unset *array_get_unused_element(array *a, data_type_t t);
data_unset *array_get_element(array *a, const char *key);
data_unset *array_replace(array *a, data_unset *du);
int array_strcasecmp(const char *a, size_t a_len, const char *b, size_t b_len);
void array_print_indent(int depth);

#endif
