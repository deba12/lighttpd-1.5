#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "config.h"


/* plugin config for all request/connections */
typedef struct {
	array *alias;
} plugin_config;

typedef struct {
	PLUGIN_DATA;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init the plugin data */
INIT_FUNC(mod_alias_init) {
	plugin_data *p;
	
	p = calloc(1, sizeof(*p));
	
	
	
	return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_alias_free) {
	plugin_data *p = p_d;
	
	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		size_t i;
		
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			array_free(s->alias);
			
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	
	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_alias_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ "alias.url",                  NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ NULL,                         NULL, T_CONFIG_UNSET,  T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = malloc(srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = malloc(sizeof(plugin_config));
		s->alias = array_init();	
		cv[0].destination = s->alias;
		
		p->config_storage[i] = s;
		
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
	}
	
	return HANDLER_GO_ON;
}

#define PATCH(x) \
	p->conf.x = s->x;
static int mod_alias_patch_connection(server *srv, connection *con, plugin_data *p, const char *stage, size_t stage_len) {
	size_t i, j;
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		plugin_config *s = p->config_storage[i];
		
		/* not our stage */
		if (!buffer_is_equal_string(dc->comp_key, stage, stage_len)) continue;
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN("alias.url"))) {
				PATCH(alias);
			}
		}
	}
	
	return 0;
}

static int mod_alias_setup_connection(server *srv, connection *con, plugin_data *p) {
	plugin_config *s = p->config_storage[0];
	UNUSED(srv);
	UNUSED(con);
		
	PATCH(alias);
	
	return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_alias_docroot_handler) {
	plugin_data *p = p_d;
	int uri_len;
	size_t k, i;
	
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	
	mod_alias_setup_connection(srv, con, p);
	for (i = 0; i < srv->config_patches->used; i++) {
		buffer *patch = srv->config_patches->ptr[i];
		
		mod_alias_patch_connection(srv, con, p, CONST_BUF_LEN(patch));
	}
	
	uri_len = con->uri.path->used - 1;
	
	for (k = 0; k < p->conf.alias->used; k++) {
		data_string *ds = (data_string *)p->conf.alias->data[k];
		int alias_len = ds->key->used - 1;
		
		if (alias_len > uri_len) continue;
		if (ds->key->used == 0) continue;
		
		if (0 == strncmp(con->uri.path->ptr, ds->key->ptr, alias_len)) {
			/* matched */
			
			buffer_copy_string_buffer(con->physical.doc_root, ds->value);
			buffer_copy_string(con->physical.rel_path, con->uri.path->ptr + alias_len);
			
			return HANDLER_GO_ON;
		}
	}
	
	/* not found */
	return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_alias_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("alias");
	
	p->init           = mod_alias_init;
	p->handle_docroot = mod_alias_docroot_handler;
	p->set_defaults   = mod_alias_set_defaults;
	p->cleanup        = mod_alias_free;
	
	p->data        = NULL;
	
	return 0;
}
