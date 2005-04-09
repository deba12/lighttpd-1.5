#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"

static void data_config_free(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	buffer_free(ds->key);
	buffer_free(ds->comp_key);
	
	array_free(ds->value);
	
	if (ds->string) buffer_free(ds->string);
#ifdef HAVE_PCRE_H
	if (ds->regex) pcre_free(ds->regex);
	if (ds->regex_study) pcre_free(ds->regex_study);
#endif
	
	free(d);
}

static void data_config_reset(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	/* reused array elements */
	buffer_reset(ds->key);
	buffer_reset(ds->comp_key);
	array_reset(ds->value);
}

static int data_config_insert_dup(data_unset *dst, data_unset *src) {
	UNUSED(dst);
	
	src->free(src);
	
	return 0;
}

static void data_config_print(data_unset *d) {
	data_config *ds = (data_config *)d;
	
	printf("{%s:\n", ds->key->ptr);
	array_print(ds->value);
	printf("}");
}


data_config *data_config_init(void) {
	data_config *ds;
	
	ds = calloc(1, sizeof(*ds));
	
	ds->key = buffer_init();
	ds->comp_key = buffer_init();
	ds->value = array_init();
	
	ds->free = data_config_free;
	ds->reset = data_config_reset;
	ds->insert_dup = data_config_insert_dup;
	ds->print = data_config_print;
	ds->type = TYPE_CONFIG;
	
	return ds;
}
