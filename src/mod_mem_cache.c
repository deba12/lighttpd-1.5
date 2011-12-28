#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "stat_cache.h"
#include "etag.h"
#include "response.h"
#include "status_counter.h"
#include "splaytree.h"

#define CONFIG_MEM_CACHE_ENABLE "mem-cache.enable"
#define CONFIG_MEM_CACHE_MAX_MEMORY "mem-cache.max-memory"
#define CONFIG_MEM_CACHE_MAX_FILE_SIZE "mem-cache.max-file-size"
#define CONFIG_MEM_CACHE_LRU_REMOVE_COUNT "mem-cache.lru-remove-count"
#define CONFIG_MEM_CACHE_EXPIRE_TIME "mem-cache.expire-time"
#define CONFIG_MEM_CACHE_FILE_TYPES "mem-cache.filetypes"
#define CONFIG_MEM_CACHE_SLRU_THRESOLD "mem-cache.slru-thresold"

typedef struct {
	/* number of cache items removed by lru when memory is full */
	unsigned short lru_remove_count;
	/* mem-cache.enable-cache */
	unsigned short enable;
	/* mem-cache.max-memory */
	off_t maxmemory; /* maxium total used memory in MB */
	/* mem-cache.max-file-size */
	off_t maxfilesize; /* maxium file size will put into memory */
	/* mem-cache.expire-time in second */
	unsigned int expires;
	/* mem-cache.filetypes */
	array  *filetypes;
	/* mem-cache.slru-thresold */
	short thresold;
} plugin_config;

#define MEM_CACHE_NUM 524288 /* 2^19 */

static int lruheader, lruend;
static unsigned long reqcount, reqhit, cachenumber;

/* use hash idea as danga's memcached */
struct cache_entry{
	short inuse;
	/* cache data */
	buffer *content;

	/* pointer for next when hash collided */
	struct cache_entry *scnext;

	/* lru info */
	unsigned int prev;
	unsigned int next;

	/* cache store time */
	time_t ct;
	/* file name */
	buffer *path;
	/* buffer to print at Last-Modified: header */
	buffer *mtime;
	/* content-type */
	buffer *content_type;
	/* etag */
	buffer *etag;
}; 

static struct cache_entry *memcache;

static unsigned long usedmemory;

/* probation lru splaytree */
splay_tree *plru;
/* structure to store probation lru info */
struct probation {
	time_t startts;
	int count;
};

typedef struct {
	PLUGIN_DATA;
	
	plugin_config **config_storage;
	
	plugin_config conf; 
} plugin_data;

/* init cache_entry table */
static struct cache_entry *cache_entry_init(void) {
	struct cache_entry *c;
	c = (struct cache_entry *) malloc(sizeof(struct cache_entry)*(MEM_CACHE_NUM+1));
	assert(c);
	memset(c, 0, sizeof(struct cache_entry)*(MEM_CACHE_NUM+1));
	return c;
}

/* free cache_entry */
static void cache_entry_free(struct cache_entry *cache) {
	if (cache == NULL) return;
	cachenumber --;
	if (cache->content) usedmemory -= cache->content->size;
	buffer_free(cache->content);
	buffer_free(cache->content_type);
	buffer_free(cache->etag);
	buffer_free(cache->path);
	buffer_free(cache->mtime);
	memset(cache, 0, sizeof(struct cache_entry));
}

/* reset cache_entry to initial state */
static void cache_entry_reset(struct cache_entry *cache) {
	if (cache == NULL) return;
	if (cache->content == NULL) cache->content = buffer_init();
	if (cache->content_type == NULL) cache->content_type = buffer_init();
	if (cache->etag == NULL) cache->etag = buffer_init();
	if (cache->path == NULL) cache->path = buffer_init();
	if (cache->mtime == NULL) cache->mtime = buffer_init();
}

/* init the plugin data */
INIT_FUNC(mod_mem_cache_init) {
	plugin_data *p;
	
	UNUSED(srv);
	p = calloc(1, sizeof(*p));
	memcache = cache_entry_init();
	lruheader = lruend = cachenumber = 0;
	reqcount = reqhit = 1;
	usedmemory = 0;
	plru = NULL;
	
	return p;
}

void free_cache_entry_chain(struct cache_entry *p) {
	struct cache_entry *c1, *c2;

	c1 = p;
	while(c1) {
		c2 = c1->scnext;
		cache_entry_free(c1);
		if (c1 != p) free(c1);
		c1 = c2;
	}

}

/* detroy the plugin data */
FREE_FUNC(mod_mem_cache_free) {
	plugin_data *p = p_d;
	size_t i;
	
	UNUSED(srv);

	if (!p) return HANDLER_GO_ON;
	
	if (p->config_storage) {
		for (i = 0; i < srv->config_context->used; i++) {
			plugin_config *s = p->config_storage[i];
			
			if (!s) continue;
			array_free(s->filetypes);
			free(s);
		}
		free(p->config_storage);
	}
	
	free(p);
	for (i = 0; i<= MEM_CACHE_NUM; i++) {
		free_cache_entry_chain(memcache+i);
	}
	free(memcache);

	while (plru) {
		if (plru->data) free(plru->data);
		plru = splaytree_delete(plru, plru->key);
	}

	return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_mem_cache_set_defaults) {
	plugin_data *p = p_d;
	size_t i = 0;
	
	config_values_t cv[] = { 
		{ CONFIG_MEM_CACHE_MAX_MEMORY, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
		{ CONFIG_MEM_CACHE_MAX_FILE_SIZE, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 1 */
		{ CONFIG_MEM_CACHE_LRU_REMOVE_COUNT, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 2 */
		{ CONFIG_MEM_CACHE_ENABLE, NULL, T_CONFIG_BOOLEAN, T_CONFIG_SCOPE_CONNECTION },       /* 3 */
		{ CONFIG_MEM_CACHE_EXPIRE_TIME, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 4 */
		{ CONFIG_MEM_CACHE_FILE_TYPES, NULL, T_CONFIG_ARRAY, T_CONFIG_SCOPE_CONNECTION },       /* 5 */
		{ CONFIG_MEM_CACHE_SLRU_THRESOLD, NULL, T_CONFIG_SHORT, T_CONFIG_SCOPE_CONNECTION },       /* 6 */
		{ NULL,                         NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
	};
	
	if (!p) return HANDLER_ERROR;
	
	p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));
	
	for (i = 0; i < srv->config_context->used; i++) {
		plugin_config *s;
		
		s = calloc(1, sizeof(plugin_config));
		s->maxmemory = 256; /* 256M default */
		s->maxfilesize = 512; /* maxium 512k */
		s->lru_remove_count = 200; /* default 200 */
		s->enable = 1; /* default to cache content into memory */
		s->expires = 0; /* default to check stat at every request */
		s->filetypes = array_init();
		s->thresold = 0; /* 0 just like normal LRU algorithm */
		
		cv[0].destination = &(s->maxmemory);
		cv[1].destination = &(s->maxfilesize);
		cv[2].destination = &(s->lru_remove_count);
		cv[3].destination = &(s->enable);
		cv[4].destination = &(s->expires);
		cv[5].destination = s->filetypes;
		cv[6].destination = &(s->thresold);
		
		p->config_storage[i] = s;
	
		if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
			return HANDLER_ERROR;
		}
		s->expires *= 60;

		if (s->thresold < 0) s->thresold = 0;
		if (s->thresold > 0)
			status_counter_set(CONST_STR_LEN("mem-cache.slru-thresold"), s->thresold);
	}
	
	return HANDLER_GO_ON;
}

/* the famous DJB hash function for strings from stat_cache.c*/
static uint32_t hashme(buffer *str) {
	uint32_t hash = 5381;
	const char *s;
	for (s = str->ptr; *s; s++) {
		hash = ((hash << 5) + hash) + *s;
	}

	hash &= ~(1 << 31); /* strip the highest bit */

	return hash;
}

static int mod_mem_cache_patch_connection(server *srv, connection *con, plugin_data *p) {
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	
	PATCH_OPTION(maxmemory);
	PATCH_OPTION(maxfilesize);
	PATCH_OPTION(lru_remove_count);
	PATCH_OPTION(enable);
	PATCH_OPTION(expires);
	PATCH_OPTION(filetypes);
	PATCH_OPTION(thresold);
	
	/* skip the first, the global context */
	for (i = 1; i < srv->config_context->used; i++) {
		data_config *dc = (data_config *)srv->config_context->data[i];
		s = p->config_storage[i];
		
		/* condition didn't match */
		if (!config_check_cond(srv, con, dc)) continue;
		
		/* merge config */
		for (j = 0; j < dc->value->used; j++) {
			data_unset *du = dc->value->data[j];
			
			if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_ENABLE))) {
				PATCH_OPTION(enable);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_MAX_FILE_SIZE))) {
				PATCH_OPTION(maxfilesize);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_MAX_MEMORY))) {
				PATCH_OPTION(maxmemory);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_FILE_TYPES))) {
				PATCH_OPTION(filetypes);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_EXPIRE_TIME))) {
				PATCH_OPTION(expires);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_LRU_REMOVE_COUNT))) {
				PATCH_OPTION(lru_remove_count);
			} else if (buffer_is_equal_string(du->key, CONST_STR_LEN(CONFIG_MEM_CACHE_SLRU_THRESOLD))) {
				PATCH_OPTION(thresold);
			}
		}
	}
	
	return 0;
}

/* free all cache-entry and init cache_entry */
static void free_all_cache_entry(server *srv) {
	int j;
	for (j = 0; j <= MEM_CACHE_NUM; j++) {
		free_cache_entry_chain(memcache+j);
	}
	memset(memcache, 0, sizeof(struct cache_entry)*(MEM_CACHE_NUM+1));
	lruheader = lruend = cachenumber = 0;
	usedmemory = 0;
	TRACE("%s", "free all state_cache data due to data inconsistence");
	status_counter_set(CONST_STR_LEN("mem-cache.memory-inuse(MB)"), usedmemory>>20);
	status_counter_set(CONST_STR_LEN("mem-cache.cached-items"), cachenumber);
}

static void free_cache_entry_by_lru(server *srv, const int num) {
	int i, d1;

	if (lruheader == 0 || lruend == 0) return;
	d1 = lruheader;
	for(i = 0; i < num; i++, d1=lruheader) {
		lruheader = memcache[d1].next;
		if (memcache[d1].inuse) {
			memcache[d1].next = memcache[d1].prev = 0;
			free_cache_entry_chain(memcache+d1);
			memcache[d1].inuse = 0;
			memset(memcache+d1, 0, sizeof(struct cache_entry));
		} else { 
			/* wrong lru data, free them all! */
			free_all_cache_entry(srv);
			break;
		}
		if (lruheader == 0) { lruheader = lruend = cachenumber = usedmemory = 0; break; }
	}
	status_counter_set(CONST_STR_LEN("mem-cache.memory-inuse(MB)"), usedmemory>>20);
	status_counter_set(CONST_STR_LEN("mem-cache.cached-items"), cachenumber);
}

/* update LRU lists */
static void update_lru(server *srv, int i) {
	int d1, d2;

	if (i == 0 || memcache[i].inuse == 0) return;
	if (lruheader == 0 || lruend == 0) { 
		/* first item */
		memcache[i].prev = memcache[i].next = 0;
		lruheader = lruend = i;
	} else if (i != lruend && i != lruheader){ 
		/* re-order lru list */
		d1 = memcache[i].prev;
		d2 = memcache[i].next;
		if (d1 == 0 && d2 == 0) { 
			/* new item */
			memcache[i].prev = lruend;
			memcache[i].next = 0;
			memcache[lruend].next = i;
			lruend = i;
		} else if (d1 == 0 || d2 == 0) {
			/* wrong lru , free all cached data and reset lru */
			free_all_cache_entry(srv);
		} else {
			memcache[d1].next = d2;
			memcache[d2].prev = d1;
			/* append to end of list */
			memcache[lruend].next = i;
			memcache[i].next = 0;
			memcache[i].prev = lruend;
			lruend = i;
		}
	} else if (i == lruend) { 
		/* end of lru, no change */
	} else if (i == lruheader) { 
		/* move header to the end*/
		lruheader = memcache[i].next;
		memcache[lruheader].prev = 0;
		memcache[i].prev = lruend;
		memcache[i].next = 0;
		memcache[lruend].next = i;
		lruend = i;
	}
}

/* read file content into buffer dst 
 * return 1 if failed
 */
static int readfile_into_buffer(server *srv, connection *con, int filesize, buffer *dst) {
	int ifd;

	if (dst == NULL) return 1;
	if (dst->size <= (size_t) filesize) return 1;
	if (-1 == (ifd = open(con->physical.path->ptr, O_RDONLY | O_BINARY))) {
		TRACE("fail to open %s: %s", con->physical.path->ptr, strerror(errno));
		return 1;
	}

	if (filesize == read(ifd, dst->ptr, filesize)) { 
		dst->ptr[filesize] = '\0';
		dst->used = filesize + 1;
		close(ifd); 
		return 0; 
	} else { 
		TRACE("fail to read %d bytes of %s into memory", filesize, con->physical.path->ptr);
		close(ifd); 
		return 1; 
	}
}

/* if HIT + not expire, set status = 1 and return ptr
 * else if HIT but expired, set status = 0 and return ptr
 * else if not HIT, set status = 0 and return NULL
 */
static struct cache_entry *check_mem_cache(server *srv, connection *con, plugin_data *p, int *status, const uint32_t i) {
	struct cache_entry *c;
	int success = 0;

	c = memcache+i;
	*status = 0;
	
	while (c) {
		if (c->path && buffer_is_equal(c->path, con->physical.path)) {
			success = 1;
			break;
		}
		c = c->scnext;
	}

	if (success) {
		if (c->inuse && p->conf.expires 
			&& (srv->cur_ts - c->ct)  <= (time_t )p->conf.expires)
			*status = 1;
		return c;
	}

	return NULL;
}

static struct cache_entry *get_mem_cache_entry(const uint32_t hash) {
	uint32_t i;
	struct cache_entry *c1, *c2;

	i = (hash & (MEM_CACHE_NUM-1))+1;
	c1 = c2 = memcache+i;
	
	/* try to find unused item first */
	while(c1 && c1->inuse) {
		c2 = c1;
		c1 = c1->scnext;
	}
	if (c1) return c1; /* use the first unused item */
	/* we need allocate new cache_entry */
	c1 = (struct cache_entry *)malloc(sizeof(struct cache_entry));
	if (c1 == NULL) return NULL;
	memset(c1, 0, sizeof(struct cache_entry));
	/* put new cache_entry into hash table */
	c2->scnext = c1;
	return c1;
}

/* return 0 when probation->count > p->conf.thresold in 24 hours or p->conf.thresold == 0
 * otherwise return 1
 */
static int check_probation_lru(server *srv, plugin_data *p, int hash) {
	splay_tree *node;
	struct probation *pr;
	int status = 1;

	if (p->conf.thresold == 0) return 0;
	node = splaytree_splay(plru, hash);
	if (node == NULL || node->key != hash) { /* first splaytree node or new node*/
		pr = (struct probation *) malloc(sizeof(struct probation));
		if (pr == NULL) { /* out of memory */
			return 1;
		}
		pr->count = 1;
		pr->startts = srv->cur_ts;
		plru = splaytree_insert(plru, hash, (void *) pr);
	} else { /* matched */
		pr = (struct probation *) node->data;
		if ((srv->cur_ts - pr->startts) > 86400) {
			/* keep track of last 24 hours only */
			pr->count = 0;
			pr->startts = srv->cur_ts;
		}
		pr->count ++;
		if (pr->count > p->conf.thresold) {
			free(pr);
			plru = splaytree_delete(plru, hash);
			status = 0;
		}
	}
	return status;
}

handler_t mod_mem_cache_subrequest(server *srv, connection *con, void *p_d) {
	plugin_data *p = p_d;
	uint32_t hash;
	int i = 0, success = 0;
	size_t m;
	stat_cache_entry *sce = NULL;
	buffer *mtime, *b;
	data_string *ds;
	struct cache_entry *cache;
	
	/* someone else has done a decision for us */
	if (con->http_status != 0) return HANDLER_GO_ON;
	if (con->uri.path->used == 0) return HANDLER_GO_ON;
	if (con->physical.path->used == 0) return HANDLER_GO_ON;
	
	/* someone else has handled this request */
	if (con->mode != DIRECT) return HANDLER_GO_ON;
	if (con->send->is_closed) return HANDLER_GO_ON;

	/* we only handle GET, POST and HEAD */
	switch(con->request.http_method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_POST:
	case HTTP_METHOD_HEAD:
		break;
	default:
		return HANDLER_GO_ON;
	}
	
	if (con->conf.range_requests && NULL != array_get_element(con->request.headers, CONST_STR_LEN("Range")))
		return HANDLER_GO_ON;

	mod_mem_cache_patch_connection(srv, con, p);
	
	if (p->conf.enable == 0|| p->conf.maxfilesize == 0) return HANDLER_GO_ON;

	hash = hashme(con->physical.path);
	i = (hash & (MEM_CACHE_NUM-1))+1;
	cache = check_mem_cache(srv, con, p, &success, i);
	reqcount ++;

	if (success == 0 || cache == NULL) {
		/* going to put content into cache */
		if (HANDLER_ERROR == stat_cache_get_entry(srv, con, con->physical.path, &sce)) {
			return HANDLER_GO_ON;
		}
		/* we only handline regular files */
#ifdef HAVE_LSTAT
		if ((sce->is_symlink == 1) && !con->conf.follow_symlink) {
			con->http_status = 403;
			buffer_reset(con->physical.path);
			return HANDLER_FINISHED;
		}
#endif

		if (!S_ISREG(sce->st.st_mode)) {
			return HANDLER_GO_ON;
		}
		/* check filetypes */
		for (m = 0; m < p->conf.filetypes->used; m++) {
			ds = (data_string *)p->conf.filetypes->data[m];
			if (!ds) return HANDLER_GO_ON;
			if (sce->content_type->used &&
			    strncmp(ds->value->ptr, sce->content_type->ptr, ds->value->used-1)==0)
				break;
		}
		if (m && m == p->conf.filetypes->used)
			return HANDLER_GO_ON;
		if (sce->st.st_size == 0 || ((sce->st.st_size >> 10) > p->conf.maxfilesize)) 
			return HANDLER_GO_ON;

		if (cache == NULL) {
			/* check probation lru now */
			if (check_probation_lru(srv, p, hash))
				return HANDLER_GO_ON;
			cache = get_mem_cache_entry(hash);
			if (cache == NULL) {
				/* may be out of memory, just return GO_ON */
				return HANDLER_GO_ON;
			}
		}
		etag_mutate(con->physical.etag, sce->etag);

		if (cache->inuse == 0 || buffer_is_equal(con->physical.etag, cache->etag) == 0) {
			/* initialze cache's buffer if needed */
			cache_entry_reset(cache);
			if (cache->content->size <= sce->st.st_size) {
				usedmemory -= cache->content->size;
				buffer_prepare_copy(cache->content, sce->st.st_size);
				usedmemory += cache->content->size;
			}
			if (readfile_into_buffer(srv, con, sce->st.st_size, cache->content)) {
				return HANDLER_GO_ON;
			}
			/* increase cachenumber if needed */
			if (cache->inuse == 0) cachenumber ++;
			cache->inuse = 1;


			if (sce->content_type->used == 0) {
				buffer_copy_string_len(cache->content_type, CONST_STR_LEN("application/octet-stream"));
			} else {
				buffer_copy_string_buffer(cache->content_type, sce->content_type);
			}
			buffer_copy_string_buffer(cache->etag, con->physical.etag);
			buffer_copy_string_buffer(cache->path, con->physical.path);
			mtime = strftime_cache_get(srv, sce->st.st_mtime);
			buffer_copy_string_buffer(cache->mtime, mtime);
			cache->ct = srv->cur_ts;
#if 0
			response_header_overwrite(srv, con, CONST_STR_LEN("X-Mem-Hit"), CONST_STR_LEN("to mem-cache"));
#endif
			status_counter_set(CONST_STR_LEN("mem-cache.memory-inuse(MB)"), usedmemory>>20);
			status_counter_set(CONST_STR_LEN("mem-cache.cached-items"), cachenumber);
		} else  {
			cache->ct = srv->cur_ts;
			reqhit ++;
#if 0
			response_header_overwrite(srv, con, CONST_STR_LEN("X-Mem-Hit"), CONST_STR_LEN("by mem-cache"));
#endif
		}
	} else {
		reqhit ++;
#if 0
		response_header_overwrite(srv, con, CONST_STR_LEN("X-Mem-Hit"), CONST_STR_LEN("by mem-cache"));
#endif
	}

	if (NULL == array_get_element(con->response.headers, CONST_STR_LEN("Content-Type"))) {
		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_BUF_LEN(cache->content_type));
	}
	
	if (NULL == array_get_element(con->response.headers, CONST_STR_LEN("ETag"))) {
	       	response_header_overwrite(srv, con, CONST_STR_LEN("ETag"), CONST_BUF_LEN(cache->etag));
	}

	/* prepare header */
	if (NULL == (ds = (data_string *)array_get_element(con->response.headers, CONST_STR_LEN("Last-Modified")))) {
		mtime = cache->mtime;
		response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"), CONST_BUF_LEN(mtime));
	} else mtime = ds->value;

	status_counter_set(CONST_STR_LEN("mem-cache.hitrate(%)"), (int) (((float)reqhit/(float)reqcount)*100));
	if (HANDLER_FINISHED == http_response_handle_cachable(srv, con, mtime, cache->etag))
		return HANDLER_FINISHED;

	b = chunkqueue_get_append_buffer(con->send);
	buffer_append_string_buffer(b, cache->content);
	buffer_reset(con->physical.path);
	update_lru(srv, i);
	if ((usedmemory >> 20) > p->conf.maxmemory) {
		/* free least used items */
		free_cache_entry_by_lru(srv, p->conf.lru_remove_count); 
	}
	con->send->is_closed = 1;
	
	return HANDLER_FINISHED;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_mem_cache_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = buffer_init_string("mem_cache");
	
	p->init        = mod_mem_cache_init;
	p->handle_physical = mod_mem_cache_subrequest;
	/*p->handle_subrequest_start = mod_mem_cache_subrequest; */
	p->set_defaults  = mod_mem_cache_set_defaults;
	p->cleanup     = mod_mem_cache_free;
	
	p->data        = NULL;
	
	return 0;
}
