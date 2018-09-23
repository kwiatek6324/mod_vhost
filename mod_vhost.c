#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_main.h"
#include "http_protocol.h"
#include "mod_core.h"

#include "apr.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_reslist.h"
#include "apr_file_io.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "ap_socache.h"
#include "util_mutex.h"





#ifdef HAVE_PGSQL
 #define HAVE_SQL
 #include "libpq-fe.h"
#endif 

#ifdef HAVE_LDAP
 #include "ldap.h"
 #include "lber.h"
#endif

#ifdef HAVE_MYSQL
 #define HAVE_SQL
 #include "mysql/mysql.h"
#endif 

#ifdef HAVE_SQLITE
 #define HAVE_SQL
 #include "sqlite3.h"
#endif


#include <time.h>

#include <string.h>
#include <strings.h>


#define MAX_LEN 1024
#define PGSQL_PORT	5432


module AP_MODULE_DECLARE_DATA mod_vhost_module;

typedef struct {
	int	enable;
        char    *dir;
        char    *poscache;
        char    *negcache;
	int	suexecenable;
        int     defuid;
        int     defgid;
	char	*defchroot;
	char	*phpdisstr;
#ifdef HAVE_PGSQL
        char    *pgsql_host;
        char     *pgsql_port;
        char    *pgsql_user;
        char    *pgsql_pass;
        char    *pgsql_db;
        char    *pgsql_select;
#endif
#ifdef HAVE_MYSQL
        char    *mysql_host;
        char    *mysql_port;
        char    *mysql_user;
        char    *mysql_pass;
        char    *mysql_db;
        char    *mysql_select;
#endif
#ifdef HAVE_LDAP
        char    *ldap_host;
        char    *ldap_port;
        char    *ldap_binddn;
        char    *ldap_bindpw;
        char    *ldap_basedn;
        char    *ldap_filter;
#endif 
#ifdef HAVE_SQLITE
	char	*sqlite_db;
        char    *sqlite_select;
#endif
        char    *debug;
	apr_array_header_t	*aliases;

	int timeout;
	apr_array_header_t *providers;
	const char *context;

} mod_vhost_config;


static apr_global_mutex_t *mod_vhost_mutex = NULL;
static ap_socache_provider_t *socache_provider = NULL;
static ap_socache_instance_t *socache_instance = NULL;
static const char *const mod_vhost_id = "mod_vhost-socache";
static int configured;

static apr_status_t remove_lock(void *data)
{
    if (mod_vhost_mutex) {
        apr_global_mutex_destroy(mod_vhost_mutex);
        mod_vhost_mutex = NULL;
    }
    return APR_SUCCESS;
}

static apr_status_t destroy_cache(void *data)
{
    if (socache_instance) {
        socache_provider->destroy(socache_instance, (server_rec*)data);
        socache_instance = NULL;
    }
    return APR_SUCCESS;
}



typedef struct {
    const char *real;
    const char *fake;
    char *handler;
} vhostalias_entry;


typedef struct {
    apr_array_header_t *aliases;
} vhost_aliases;





/************************************************************************************************/
#ifdef HAVE_PGSQL
PGconn  *pgsql_connect(mod_vhost_config   *vc)
{
PGconn  *con;
char    port[32];
apr_snprintf(port,32,"%d",PGSQL_PORT);

con=PQsetdbLogin(vc->pgsql_host,vc->pgsql_port,NULL,NULL,vc->pgsql_db,vc->pgsql_user,vc->pgsql_pass);

if (PQstatus(con)==CONNECTION_BAD)
        {
        PQfinish(con);
        return NULL;
        };

return con;
};


PGresult *pgsql_tuples(PGconn *con,char sql[MAX_LEN])
{
PGresult        *res;

if (con==NULL) {
        return NULL;
        };

res=PQexec(con,sql);
if (!res || PQresultStatus(res)!=PGRES_TUPLES_OK) {
        return NULL;
        };

return res;
};

#endif


#ifdef HAVE_LDAP

static LDAP *ldap_open_and_bind (char *host,int port,char *username,char *password) {
  LDAP *ld;
  int res;


  ld=ldap_open(host,389);
  if (!ld)
    return NULL;

  if (username == NULL) {
    res = ldap_simple_bind_s(ld,NULL,NULL);
  } else {
    res = ldap_simple_bind_s(ld,username,password);
  }
  if (res!=LDAP_SUCCESS) {
    ldap_unbind(ld);
    return NULL;
  }

  return ld;
}

#endif


#ifdef HAVE_MYSQL

MYSQL  *mysql_connct(mod_vhost_config   *vc)
{
MYSQL *mysql=NULL;

mysql=mysql_init(NULL);

if (!mysql_real_connect(mysql,vc->mysql_host,vc->mysql_user,vc->mysql_pass,vc->mysql_db,vc->mysql_port!=NULL?atoi(vc->mysql_port):3306,NULL,0)) {
        mysql_close(mysql);
        return NULL;
        };

return mysql;
};


MYSQL_RES *mysql_tuples(MYSQL *con,char sql[MAX_LEN])
{
int     i;

if (con==NULL) {
        return NULL;
        };

i=mysql_real_query(con,sql,(unsigned int) strlen(sql));

if (i!=0) {
        return NULL;
        };

return mysql_use_result(con);

return NULL;
};

#endif


#ifdef HAVE_SQLITE
sqlite3  *sqlite_connect(mod_vhost_config   *vc)
{
sqlite3 *sqconn;
int rc;

rc=sqlite3_open(vc->sqlite_db,&sqconn);

if (rc!=0) {
	return NULL;
	} else {
	return sqconn;
	};
};



int sqlite_tuples(server_rec *s,sqlite3 *sqlite,char sql[MAX_LEN],char ***wynik, int *cnt)
{
int     rc;

if (sqlite==NULL) {
        return -1;
        };

int sqlite_callback(void *args, int numCols, char **results, char **columnNames){
int i=0;
if ((*cnt)<7) {
       wynik[(int)(*cnt)]=strdup(results[0]);
       (*cnt)++;
       };
return 0;
}
rc=sqlite3_exec(sqlite,sql,&sqlite_callback,NULL,NULL);

return rc;
};


#endif



static char *get_db_cache(server_rec *s,request_rec *r,char *prefix,char *hostname,char *dbfile,int debug)
{
mod_vhost_config   *vc;

int                     ret;
char                    *dr=NULL;
char			key[MAX_LEN];

unsigned char val[MAX_LEN];
unsigned int vallen = MAX_LEN - 1;


vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (hostname==NULL || dbfile==NULL) {
        ap_log_rerror(APLOG_MARK,APLOG_WARNING,0,r,APLOGNO(00000) "[mod_vhost.c]: no hostname/dbfile received by get_db_cache");
        return NULL;
        };

apr_status_t rv;
apr_snprintf(key,MAX_LEN,"%s:%s:%s",dbfile,prefix,hostname);


rv = socache_provider->retrieve(socache_instance, r->server, (unsigned char*)key, strlen(key), val, &vallen, r->pool);

if (APR_STATUS_IS_NOTFOUND(rv)) { 
    if (debug>0) { ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00001) "[mod_vhost.c]: Cache entry not found for [%s]",key); }
    return NULL; 
  } else 
if (rv == APR_SUCCESS) { 
    val[vallen] = 0; 
   if (debug>0)  ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00002) "[mod_vhost.c]: Cache entry found for [%s]=>[%s]", key,val);
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(0003) "[mod_vhost.c]: Error accessing cache [%s]",key);
    return NULL;
}


return apr_pstrdup(r->pool,val);

}


static char *set_db_cache(server_rec *s,request_rec *r,char *prefix,char *hostname,char *value,char *dbfile,int debug)
{

int                     ret;
char                    *dr=NULL;

char			key[MAX_LEN];
mod_vhost_config	*vc;

apr_status_t rv;
apr_time_t expiry;

vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (!configured ) { return NULL; }

if (hostname==NULL || value==NULL || dbfile==NULL) {
  ap_log_error(APLOG_MARK,APLOG_WARNING,0,s, APLOGNO(00010) "[mod_vhost.c]: set_db_cache: no hostname/docroot/dbfile received by set_db_cache ");
  return NULL;
  };


apr_snprintf(key,MAX_LEN,"%s:%s:%s",dbfile,prefix,hostname);

rv = apr_global_mutex_trylock(mod_vhost_mutex);
if (APR_STATUS_IS_EBUSY(rv)) {
  ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r, APLOGNO(00011) "[mod_vhost.c]: set_db_cache: Cache mutex busy for [%s]", key);
  return NULL;
  } else 
if (rv != APR_SUCCESS) {
  ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00012) "[mod_vhost.c]: set_db_cache: Failed to cache for [%s]", key);
  return NULL;
}

expiry = apr_time_now() + apr_time_from_sec(vc->timeout);

rv = socache_provider->store(socache_instance, r->server, (unsigned char*)key, strlen(key), expiry, (unsigned char*)value, strlen(value), r->pool);
if (rv == APR_SUCCESS) {
  ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(00013) "[mod_vhost.c]: set_db_cache: Cached for [%s]->[%s]", key, value);
  } else {
  ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00014) "[mod_vhost.c]: set_db_cache: Failed to cache for [%s]->[%s]", key, value);
}

rv = apr_global_mutex_unlock(mod_vhost_mutex);
if (rv != APR_SUCCESS) { ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00015) "[mod_vhost.c]: set_db_cache: Failed to release mutex!"); }

return NULL;

};


#ifdef HAVE_PGSQL
static char *get_pgsql_webinfo(server_rec *s,request_rec *r,char *hostname,int debug)
{
mod_vhost_config   	*vc;

char                    *dr=NULL;
char                    filter[MAX_LEN];
char			*val;

PGconn                  *conn;
PGresult 		*res;
int                     n;


vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]:  No hostname received by get_pgsql_dr ");
        return NULL;
        };

if (debug>0) {
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: host: %s",vc->pgsql_host);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: port: %s",vc->pgsql_port);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: user: %s",vc->pgsql_user);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: pass: %s",vc->pgsql_pass);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->pgsql_db);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->pgsql_select);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: Positive Ident: %s",vc->poscache);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: Negative Ident: %s",vc->negcache);
	ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: SOCache Timeout : %d",vc->timeout);
	}


if (vc->pgsql_host==NULL ||
        vc->pgsql_port==NULL ||
        vc->pgsql_user==NULL ||
        vc->pgsql_pass==NULL ||
        vc->pgsql_db==NULL ||
        vc->pgsql_select==NULL )
        {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]:get_pgsql_dr: Dont have all needed PGSQL_SETTINGS");
} else {

        conn=pgsql_connect(vc);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_pgsql_dr: Cant bind to pgsql server");
        } else {
                if (debug>0) { ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_pgsql_dr: Connection established."); }
                apr_snprintf(filter,MAX_LEN,vc->pgsql_select,r->hostname);

                if (debug>0) { ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_pgsql_dr: Filter: %s",filter); }
                res=pgsql_tuples(conn,filter);

                if (res==NULL) {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: pgsql search error");
                } else {
                        n=PQntuples(res);

                        if (n!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"[mod_vhost.c]: No single entry for filter: %s",filter);
                        } else {
                                val=PQgetvalue(res,0,0);
                                if (val!=NULL && strlen(val)>0) {
                                        dr=apr_palloc(r->pool,strlen(val)+1);
					strncpy(dr,val,strlen(val));
					dr[strlen(val)]='\0';
                                        if (debug>0) { ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_pgsql_dr: got %s from pgsql",dr); }

                                } else {
					dr=NULL;
				};

                        }; /* n!=1 */
                }; /* res!=PGSQL_SUCCESS */

                if (conn!=NULL) PQfinish(conn);

        }; /* conn=null */

}; /* vc->pgsql_host==NULL itp */

return dr;
}

#endif




#ifdef HAVE_LDAP

static char *get_ldap_webinfo(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config       *vc;

char                    *dr=NULL;
char                    filter[MAX_LEN];
char                    **val;

LDAP                    *conn;
LDAPMessage             *msg,*entry;
int                     res;
int                     scope=LDAP_SCOPE_SUBTREE;
int                     n;


vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);



if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,s, "mod_vhost.c:  No hostname received by get_ldap_dr ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: host: %s",vc->ldap_host);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: port: %s",vc->ldap_port);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: binddn: %s",vc->ldap_binddn);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: bindpw: %s",vc->ldap_bindpw);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: basedn: %s",vc->ldap_basedn);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: filter: %s",vc->ldap_filter);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "mod_vhost.c: CONF: database: %s",vc->poscache);

if (vc->ldap_host==NULL ||
        vc->ldap_port==NULL ||
        vc->ldap_binddn==NULL ||
        vc->ldap_bindpw==NULL ||
        vc->ldap_basedn==NULL ||
        vc->ldap_filter==NULL )
        {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"mod_vhost.c:get_ldap_dr: Dont have all needed LDAP_SETTINGS");
} else {

        conn=ldap_open_and_bind(vc->ldap_host,atoi(vc->ldap_port),vc->ldap_binddn,vc->ldap_bindpw);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"mod_vhost.c: get_ldap_dr: Cant bind to ldap server");
        } else {
                ap_log_error(APLOG_MARK,APLOG_NOTICE,0,s,"mod_vhost.c: get_ldap_dr: Connection established.");
                apr_snprintf(filter,MAX_LEN,vc->ldap_filter,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"mod_vhost.c: get_ldap_dr: Filter: %s",filter);
                res=ldap_search_s(conn,vc->ldap_basedn,scope,filter,NULL,0,&msg);

                if (res!=LDAP_SUCCESS)
                        {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"mod_vhost.c: ldap search error");
                } else {
                        n=ldap_count_entries(conn,msg);

                        if (n!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"mod_vhost.c: No single entry for filter: %s",filter);
                        } else {
                                entry=ldap_first_entry(conn,msg);
                                val=ldap_get_values(conn,entry,"domaindocumentroot");
                                if (val!=NULL) {
                                        dr=apr_palloc(r->pool,strlen(val[0])+1);
                                        apr_snprintf(dr,strlen(val[0])+1,"%s",val[0]);
                                        ap_log_error(APLOG_MARK,APLOG_NOTICE,0,s,"mod_vhost.c: get_ldap_dr: got %s from ldap",dr);
                                };

                        }; /* n!=1 */
                }; /* res!=LDAP_SUCCESS */

                if (conn!=NULL) ldap_unbind(conn);

        }; /* conn=null */

}; /* vc->ldap_host==NULL itp */


return dr;
}

#endif


#ifdef HAVE_MYSQL 

static char *get_mysql_webinfo(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config        *vc;

char                    *dr=NULL;
char                    filter[MAX_LEN];
char                    *val;
int                     n;

MYSQL			*conn;
MYSQL_RES		*res;
MYSQL_ROW		row;



vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]:  get_mysql_webinfo: No hostname received ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: host: %s",vc->mysql_host);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: port: %s",vc->mysql_port);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: user: %s",vc->mysql_user);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: pass: %s",vc->mysql_pass);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->mysql_db);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->mysql_select);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: database: %s",vc->poscache);


if (vc->mysql_host==NULL ||
        vc->mysql_port==NULL ||
        vc->mysql_user==NULL ||
        vc->mysql_pass==NULL ||
        vc->mysql_db==NULL ||
        vc->mysql_select==NULL )
        {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_webinfo: Dont have all needed Mysql Settings");
} else {

        conn=mysql_connct(vc);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_webinfo: cant connect to SQL server");
        } else {
                ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_mysql_webinfo: connection established.");
                apr_snprintf(filter,MAX_LEN,vc->mysql_select,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_mysql_webinfo: select: %s",filter);
                res=mysql_tuples(conn,filter);

                if (res==NULL) {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_webinfo: search error");
                } else {
                        n=mysql_num_fields(res);

                        if (n!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"[mod_vhost.c]: get_mysql_webinfo no single entry for query: %s",filter);
                        } else {
				row=mysql_fetch_row(res);
				if (row!=NULL) {
                                	val=row[0];
                                	if (val!=NULL && strlen(val)>0) {
                                        	dr=apr_palloc(r->pool,strlen(val+1));
                                        	apr_snprintf(dr,strlen(val)+1,"%s",val);
                                        	ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_mysql_webinfo: got %s from mysql",dr);
                                	} else {
                                        	dr=NULL;
                                	};
				}

                        }; /* n!=1 */
                }; /* res!=PGSQL_SUCCESS */

                if (conn!=NULL) mysql_close(conn);

        }; /* conn=null */

}; /* vc->pgsql_host==NULL itp */

return dr;
}

#endif


#ifdef HAVE_SQLITE
static char *get_sqlite_webinfo(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config        *vc;

char                    *dr=NULL;
char                    filter[MAX_LEN];
char                    *val;
int                     n;

sqlite3			 *conn;
char			*wynik[8];
int			cnt=0;
int			rc;



vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]:  get_sqlite_webinfo: No hostname received ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->sqlite_db);
ap_log_error(APLOG_MARK, APLOG_WARNING, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->sqlite_select);


if (vc->sqlite_db==NULL || vc->sqlite_select==NULL) {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_webinfo: Dont have all needed Sqlite Settings");
} else {

        conn=sqlite_connect(vc);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_webinfo: cant connect to SQLte server");
        } else {
                ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_sqlite_webinfo: connection established.");
                apr_snprintf(filter,MAX_LEN,vc->sqlite_select,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_sqlite_webinfo: select: %s",filter);
                rc=sqlite_tuples(s,conn,filter,(char ***)&wynik,&cnt);


                if (rc<0) {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_webinfo: search error");
                } else {
                        if (cnt!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"[mod_vhost.c]: get_sqlite_webinfo no single entry for query: [%s], got %d",filter,cnt);
                        } else {
                                val=wynik[0];
                                if (val!=NULL && strlen(val)>0) {
                                        dr=apr_palloc(r->pool,strlen(val+1));
                                        apr_snprintf(dr,strlen(val)+1,"%s",val);
                                        ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: get_sqlite_webinfo: got %s from sqlite",dr);
                                } else {
                                        dr=NULL;
                                };

                        }; /* n!=1 */
                }; /* res!=PGSQL_SUCCESS */

                if (conn!=NULL) sqlite3_close(conn);

        }; /* conn=null */

}; /* vc->pgsql_host==NULL itp */

return dr;
}

#endif



static char *check_alias(request_rec *r, apr_array_header_t *aliases)
{
vhostalias_entry 	*entries = (vhostalias_entry *) aliases->elts;
char 			*found = NULL;
int			i;

for (i = 0; i < aliases->nelts; ++i) {
	vhostalias_entry *p = &entries[i];

	
	if (r->uri!=NULL && p->fake!=NULL && strncmp(p->fake,r->uri,strlen(p->fake))==0)
		{

		return apr_pstrcat(r->pool,p->real,r->uri + strlen(p->fake),NULL);

		};
	};


return NULL;

};










/************************************************************************************************/


static int mod_vhost_trans_uri(request_rec *r)
{
mod_vhost_config	*vc=(mod_vhost_config *) ap_get_module_config(r->server->module_config,&mod_vhost_module);
//core_server_config 	*conf;
server_rec		*s;

//conf = ap_get_module_config(r->server->module_config, &core_module); 
#ifdef HAVE_PGSQL
PGconn                  *conn;
PGresult                *msg,*entry;
#endif

char *info;
char *documentroot;
char *php_version;
char *uri;
char		*dr=NULL;
char		filter[MAX_LEN];
int		debug=0;


uri=r->uri;


if (vc->enable==0) {
	return DECLINED;
	};


s=r->server;

conn_rec *c = r->connection;

if (vc->debug && strcmp(r->useragent_ip ,vc->debug)==0) { debug=1; }


if ((char *)r->hostname==NULL || strlen(r->hostname)==0 )
	{
	if (debug>0) {	ap_log_error(APLOG_MARK, APLOG_ERR, 0,s, "[mod_vhost.c]: No Hostname recived by trans_uri");}
	return DECLINED;
	};

if (debug>0) { ap_log_error(APLOG_MARK, APLOG_WARNING,0,s,"Received: [%s]",r->hostname); }

if ((info=check_alias(r,vc->aliases))!=NULL) {

	if (debug>0) { ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: Got Alias [%s]->[%s]",r->uri,info); }

        r->filename=apr_pstrcat(r->pool,vc->dir,info,NULL);

	return OK;

	};


if (vc->negcache!=NULL) {
	info=get_db_cache(r->server,r,(char *)"info",(char *)r->hostname,vc->negcache,debug);
	if (info!=NULL && !strcmp(info,"NOT_FOUND")) {
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"mod_vhost: hostname [%s] found in negative Cache",(char *)r->hostname);
		return DECLINED;
		};
	} ;


if (vc->poscache!=NULL) {
	info=get_db_cache(r->server,r,(char *)"info",(char *)r->hostname,vc->poscache,debug);
	if (info==NULL) {
		#ifdef HAVE_PGSQL
		info=get_pgsql_webinfo(r->server,r,(char *)r->hostname,debug);
		#endif
		#ifdef HAVE_LDAP
		info=get_ldap_webinfo(r->server,r,(char *)r->hostname,debug);
		#endif
		#ifdef HAVE_MYSQL
		info=get_mysql_webinfo(r->server,r,(char *)r->hostname,debug);
		#endif
		#ifdef HAVE_SQLITE
		info=get_sqlite_webinfo(r->server,r,(char *)r->hostname,debug);
		#endif
		if (info==NULL) {
			ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: hostname not found in database [%s]",(char *)r->hostname);
			} else {
			set_db_cache(r->server,r,"info",(char *)r->hostname,(char *)info,vc->poscache,debug);
			if (debug>0) {  ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: received from database[%s]->[%s]",(char *)r->hostname,info); }
			};
		};

	if (info==NULL) {
		set_db_cache(r->server,r,"info",(char *)r->hostname,"NOT_FOUND",vc->negcache,debug);
		return DECLINED;
		};

	if (debug>0) { ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c] info: [%s][%d]",info,strlen(info)); };

	//info[strlen(info)]='\0';

	char *strtok_state;
	char *key;
	int  c=0;

	key = apr_strtok(info, ":", &strtok_state);
	while (key) {

		if (c==0) { documentroot=apr_pstrdup(r->pool,key); }
		if (c==1) { php_version=apr_pstrdup(r->pool,key); }

		key = apr_strtok(NULL, ":", &strtok_state);
		c++;
		}

	r->server->server_hostname = apr_pstrdup(r->pool, r->hostname); // prepare server hostname

	r->filename=apr_pstrcat(r->pool,vc->dir,info,uri,NULL);
	ap_no2slash(r->filename);

	if (debug>0) {
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"Document Root[%s]",documentroot);
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"PHP Version [%s]",php_version);
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"Server Name [%s]",r->server->server_hostname);
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"Filename [%s]",r->filename);
		ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"URI [%s]",r->uri);
	}


	ap_set_context_info(r, NULL, documentroot);
	ap_set_document_root(r, documentroot);

	apr_table_setn(r->subprocess_env, "PHP_VERSION", apr_pstrdup(r->pool,php_version));

	return DECLINED;
	} else {
	return DECLINED;
	};

return DECLINED;
};


static void mod_vhost_child_init(apr_pool_t *p, server_rec *s)
{
    const char *lock;
    apr_status_t rv;
    if (!configured) { return;}
    lock = apr_global_mutex_lockfile(mod_vhost_mutex);
    rv = apr_global_mutex_child_init(&mod_vhost_mutex, lock, p);
    if (rv != APR_SUCCESS) { ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, APLOGNO(00020) "[mod_vhost.c]: error initialising mutex"); }
}

static int mod_vhost_precfg(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptmp)
{
    apr_status_t rv = ap_mutex_register(pconf, mod_vhost_id, NULL, APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(00030) "[mod_vhost.c]: error registering mutex [%s]", mod_vhost_id);
        return 500; 
      }
    socache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, AP_SOCACHE_DEFAULT_PROVIDER, AP_SOCACHE_PROVIDER_VERSION);
    configured = 0;
    return OK;
}

static int mod_vhost_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                   apr_pool_t *ptmp, server_rec *s)
{
    apr_status_t rv;
    static struct ap_socache_hints mod_vhost_hints = {64, 32, 60000000};
    const char *errmsg;

    if (!configured) { return OK;    }

    if (socache_provider == NULL) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, plog, APLOGNO(00040) "[mod_vhost.c]:Please select socache provider with ModVhostSOCache");
        return 500; 
    }

    if (socache_instance == NULL) {
        errmsg = socache_provider->create(&socache_instance, NULL, ptmp, pconf);
        if (errmsg) {
            ap_log_perror(APLOG_MARK, APLOG_CRIT, 0, plog, APLOGNO(00041) "[mod_vhost.c]: Failed to create mod_socache_shmcb socache instance: %s", errmsg);
            return 500;
        }
    }

    rv = ap_global_mutex_create(&mod_vhost_mutex, NULL, mod_vhost_id, NULL, s, pconf, 0);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(00042) "[mod_vhost.c]: Failed to create mutex[%s]", mod_vhost_id);
        return 500; 
    }
    apr_pool_cleanup_register(pconf, NULL, remove_lock, apr_pool_cleanup_null);

    rv = socache_provider->init(socache_instance, mod_vhost_id, &mod_vhost_hints, s, pconf);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, plog, APLOGNO(00043) "[mod_vhost.c]: Failed to initialise cache [%s]", mod_vhost_id);
        return 500; 
    }
    apr_pool_cleanup_register(pconf, (void*)s, destroy_cache, apr_pool_cleanup_null);
    return OK;
}





/***** config *****/

static void *mod_vhost_create_cfg(apr_pool_t *p, server_rec * s)
{
mod_vhost_config *vc;

vc= (mod_vhost_config *) apr_pcalloc(p,sizeof(mod_vhost_config));

vc->dir="/www";
vc->poscache="/tmp/positive.db";
vc->negcache="/tmp/negative.db";
vc->defuid=65534;
vc->defgid=65534;
vc->defchroot="/tmp";
vc->phpdisstr="/nophp/";
#ifdef HAVE_PGSQL
vc->pgsql_host="localhost";
vc->pgsql_port="5432";
vc->pgsql_user=NULL;
vc->pgsql_pass=NULL;
vc->pgsql_db=NULL;
vc->pgsql_select="select documentroot,uid,gid from www where domainname=%s";
#endif
#ifdef HAVE_LDAP
vc->ldap_host="ldap";
vc->ldap_port="389";
vc->ldap_binddn="cn=Directory Manager";
vc->ldap_bindpw="secret";
vc->ldap_basedn="o=top";
vc->ldap_filter="(domainname=%s)";
#endif
#ifdef HAVE_MYSQL
vc->mysql_host="localhost";
vc->mysql_port="3306";
vc->mysql_user=NULL;
vc->mysql_pass=NULL;
vc->mysql_db=NULL;
vc->mysql_select="select documentroot,uid,gid from www where domainname=%s";
#endif
#ifdef HAVE_SQLITE
vc->sqlite_db="/tmp/baza.db";
vc->sqlite_select="select documentroot,uid,gid from www where domainname=%s";
#endif

vc->timeout=0;
vc->context="modvhost";

vc->debug=NULL;

vc->aliases = apr_array_make(p, 20, sizeof(vhostalias_entry));


return (void *)vc;
};


static const char *mod_vhost_set_enable(cmd_parms *cmd, void *dummy, int enabled)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->enable = (enabled) ? 1 : 0;
    return NULL;
}

static const char *mod_vhost_set_server(cmd_parms *cmd, void *dummy, char *srv, char *port)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
#ifdef HAVE_PGSQL
    conf->pgsql_host = apr_pstrdup(cmd->pool,srv);
    conf->pgsql_port = apr_pstrdup(cmd->pool,port);
#endif
#ifdef HAVE_MYSQL
    conf->mysql_host = apr_pstrdup(cmd->pool,srv);
    conf->mysql_port = apr_pstrdup(cmd->pool,port);
#endif
#ifdef HAVE_LDAP
    conf->ldap_host = apr_pstrdup(cmd->pool,srv);
    conf->ldap_port = apr_pstrdup(cmd->pool,port);
#endif
    return NULL;
}

#ifdef HAVE_SQL

static const char *mod_vhost_set_user(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
#ifdef HAVE_PGSQL
    conf->pgsql_user = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_MYSQL
    conf->mysql_user = apr_pstrdup(cmd->pool,val);
#endif

    return NULL;
}

static const char *mod_vhost_set_pass(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
#ifdef HAVE_PGSQL
    conf->pgsql_pass = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_MYSQL
    conf->mysql_pass = apr_pstrdup(cmd->pool,val);
#endif
    return NULL;
}

static const char *mod_vhost_set_db(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
#ifdef HAVE_PGSQL
    conf->pgsql_db = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_MYSQL
    conf->mysql_db = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_SQLITE
    conf->sqlite_db = apr_pstrdup(cmd->pool,val);
#endif
    return NULL;
}

static const char *mod_vhost_set_select(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
#ifdef HAVE_PGSQL
    conf->pgsql_select = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_MYSQL
    conf->mysql_select = apr_pstrdup(cmd->pool,val);
#endif
#ifdef HAVE_SQLITE
    conf->sqlite_select = apr_pstrdup(cmd->pool,val);
#endif
    return NULL;
}

#endif

#ifdef HAVE_LDAP

static const char *mod_vhost_set_binddn(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->ldap_binddn = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_bindpw(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->ldap_bindpw = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_basedn(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->ldap_basedn = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_filter(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->ldap_filter = apr_pstrdup(cmd->pool,val);
    return NULL;
}

#endif

static const char *mod_vhost_set_debug(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->debug = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_rootdir(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->dir = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_positive(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->poscache = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_negative(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->negcache = apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_phpdisstr(cmd_parms *cmd, void *dummy, char *val)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->phpdisstr= apr_pstrdup(cmd->pool,val);
    return NULL;
}

static const char *mod_vhost_set_socache(cmd_parms *cmd, void *dummy, char *arg)
  {
 //   const char *errmsg = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    const char *sep, *name;
    const char *errmsg;

  //  if (errmsg) return errmsg;

    /* Argument is of form 'name:args' or just 'name'. */
    sep = ap_strchr_c(arg, ':');
    if (sep) {
        name = apr_pstrmemdup(cmd->pool, arg, sep - arg);
        sep++;
    }
    else {
        name = arg;
    }

    socache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name, AP_SOCACHE_PROVIDER_VERSION);
    if (socache_provider == NULL) {
        errmsg = apr_psprintf(cmd->pool, "[mod_vhost.c]:Unknown socache provider '%s' ",arg);
      } else {
        errmsg = socache_provider->create(&socache_instance, sep, cmd->temp_pool, cmd->pool);
    }

    if (errmsg) {
        errmsg = apr_psprintf(cmd->pool, "[mod_vhost.c]: ModVhostSOCache: %s", errmsg);
      }
    configured =1;
    return errmsg;
}

static const char *mod_vhost_set_socache_timeout(cmd_parms *cmd, void *dummy, char *arg)
  {
  mod_vhost_config *conf = (mod_vhost_config *)ap_get_module_config(cmd->server->module_config, &mod_vhost_module);

  conf->timeout=atoi(arg);
  return NULL;
}




static const char *mod_vhost_set_alias(cmd_parms *cmd, void *dummy, char *fake, char *real)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);

    vhostalias_entry *new = apr_array_push(conf->aliases);
    vhostalias_entry *entries = (vhostalias_entry *)conf->aliases->elts;
    new->fake=fake;
    new->real=real;


    return NULL;
}

/* suexec support */

static const char *mod_vhost_set_suexec_enable(cmd_parms *cmd, void *dummy, int enabled)
{
mod_vhost_config *conf =
(mod_vhost_config *)ap_get_module_config(cmd->server->module_config,
                                                        &mod_vhost_module);
    conf->suexecenable = (enabled) ? 1 : 0;
    return NULL;
}





/***** config *****/

static void mod_vhost_register_hooks(apr_pool_t *p) {
//	static const char * const vhSucc[]={ "mod_alias.c", NULL };
		ap_hook_pre_config(mod_vhost_precfg, NULL, NULL, APR_HOOK_MIDDLE);
		ap_hook_post_config(mod_vhost_post_config, NULL, NULL, APR_HOOK_MIDDLE);
		ap_hook_child_init(mod_vhost_child_init, NULL,NULL,APR_HOOK_MIDDLE);
        ap_hook_translate_name(mod_vhost_trans_uri, NULL, NULL, APR_HOOK_FIRST);
};


static const command_rec mod_vhost_cmds[] = {
	AP_INIT_TAKE1("ModVhostEnable",(void *)mod_vhost_set_enable, NULL, RSRC_CONF, "Set on or off to disable mod_vhost"),
	AP_INIT_TAKE1("ModVhostSuExecEnable",(void *)mod_vhost_set_suexec_enable, NULL, RSRC_CONF, "Set on or off to disable mod_vhost suexec support"),
	AP_INIT_TAKE2("ModVhostServer",(void *)mod_vhost_set_server, NULL, RSRC_CONF, "Set Server used for connection"),
	AP_INIT_TAKE1("ModVhostPHPDisableSubStr",(void *)mod_vhost_set_phpdisstr, NULL, RSRC_CONF, "Set substring in docroot where disable PHP"),
    AP_INIT_TAKE1("ModVhostSOCache",(void *)mod_vhost_set_socache , NULL, RSRC_CONF,"Socache provider"),
    AP_INIT_TAKE1("ModVhostSOCacheTimeout",(void *)mod_vhost_set_socache_timeout , NULL, RSRC_CONF,"Socache Timeout in s"),
#ifdef HAVE_SQL
	AP_INIT_TAKE1("ModVhostUser",(void *)mod_vhost_set_user, NULL, RSRC_CONF, "Set User used for connection"),
	AP_INIT_TAKE1("ModVhostPass",(void *)mod_vhost_set_pass, NULL, RSRC_CONF, "Set Pass used for connection"),
	AP_INIT_TAKE1("ModVhostDb",(void *)mod_vhost_set_db, NULL, RSRC_CONF, "Set Database used for connection"),
	AP_INIT_TAKE1("ModVhostSelect",(void *)mod_vhost_set_select, NULL, RSRC_CONF, "Set Select used for connection"),
#endif
#ifdef HAVE_LDAP
        AP_INIT_TAKE1("ModVhostBinddn",(void *)mod_vhost_set_binddn, NULL, RSRC_CONF, "Set User used for connection"),
        AP_INIT_TAKE1("ModVhostBindpw",(void *)mod_vhost_set_bindpw, NULL, RSRC_CONF, "Set Pass used for connection"),
        AP_INIT_TAKE1("ModVhostBasedn",(void *)mod_vhost_set_basedn, NULL, RSRC_CONF, "Set Database used for connection"),
        AP_INIT_TAKE1("ModVhostFilter",(void *)mod_vhost_set_filter, NULL, RSRC_CONF, "Set Select used for connection"),
#endif
	AP_INIT_TAKE1("ModVhostDebug",(void *)mod_vhost_set_debug, NULL, RSRC_CONF, "Set Debug for module"),
	AP_INIT_TAKE1("ModVhostRootDir",(void *)mod_vhost_set_rootdir, NULL, RSRC_CONF, "Set RootPrefix for documentroot"),
	AP_INIT_TAKE1("ModVhostPositiveCache",(void *)mod_vhost_set_positive, NULL, RSRC_CONF, "Set PositiveCache file for module"),
	AP_INIT_TAKE1("ModVhostNegativeCache",(void *)mod_vhost_set_negative, NULL, RSRC_CONF, "Set NegativeCache file for module"),
	AP_INIT_TAKE2("ModVhostAlias",(void *)mod_vhost_set_alias, NULL, RSRC_CONF, "Set Alias directive for module"),
	{ NULL }
};



module AP_MODULE_DECLARE_DATA mod_vhost_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	mod_vhost_create_cfg, 
	NULL,
	mod_vhost_cmds,
	mod_vhost_register_hooks
};

