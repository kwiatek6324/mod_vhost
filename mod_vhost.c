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
#include <db.h>

#include <string.h>
#include <strings.h>



#define PGSQL_PORT	5432


module AP_MODULE_DECLARE_DATA mod_vhost_module;

typedef struct {
	int	enable;
        char    *dir;
        char    *poscache;
        char    *negcache;
        int     minuid;
        int     mingid;
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
} mod_vhost_config;


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
snprintf(port,32,"%d",PGSQL_PORT);

con=PQsetdbLogin(vc->pgsql_host,vc->pgsql_port,NULL,NULL,vc->pgsql_db,vc->pgsql_user,vc->pgsql_pass);

if (PQstatus(con)==CONNECTION_BAD)
        {
        PQfinish(con);
        return NULL;
        };

return con;
};


PGresult *pgsql_tuples(PGconn *con,char sql[1024])
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


MYSQL_RES *mysql_tuples(MYSQL *con,char sql[1024])
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



int sqlite_tuples(server_rec *s,sqlite3 *sqlite,char sql[1024],char ***wynik, int *cnt)
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



static char *get_db_docroot(server_rec *s,request_rec *r,char *hostname,char *dbfile)
{
mod_vhost_config   *vc;

DB                      *dbp;
DBT                     key, data;

int                     ret;
char                    *dr=NULL;


vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (hostname==NULL || dbfile==NULL)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: no hostname/dbfile received by get_dr");
        return NULL;
        };

if ((ret = db_create(&dbp, NULL, 0)) != 0)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: db_create: %s", db_strerror(ret)); return NULL;
        }

if ((ret = dbp->open(dbp, NULL,dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0)
        {
        dbp->err(dbp, ret, "DBP Open Error: %s", dbfile);
        }

memset(&key, 0, sizeof(key));
memset(&data, 0, sizeof(data));

key.data = (char *)hostname;
key.size = strlen(hostname);

if (vc->debug>0)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_db_dr: hostname: %s[%d]",key.data,key.size);
        };

if ((ret = dbp->get(dbp, NULL, &key, &data, 0)) == 0)
        {
        dr = apr_palloc(r->pool, data.size + 1);
        strncpy(dr,data.data,data.size);
        dr[data.size]='\0';
        if (vc->debug>0)
                {
                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: getdbdocroot: got: %s[%d]",data.data,data.size);
                };
        };

if ((ret=dbp->close(dbp, 0))!=0)
        {
        dbp->err(dbp, ret, "DB->put");
        };

return dr;

}


static char *set_db_docroot(server_rec *s,request_rec *r,char *hostname,char *docroot,char *dbfile)
{
DB                      *dbp;
DBT                     key, data;

int                     ret;
char                    *dr=NULL;

if (hostname==NULL || docroot==NULL || dbfile==NULL)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: set_db_docroot: no hostname/docroot/dbfile received by set_db_dr ");
        return NULL;
        };

if ((ret = db_create(&dbp, NULL, 0)) != 0)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s, "db_create: %s", db_strerror(ret)); exit (1);
        }

if ((ret = dbp->open(dbp, NULL,dbfile, NULL, DB_BTREE, DB_CREATE, 0664)) != 0)
        {
        dbp->err(dbp, ret, "DB open Error: %s", dbfile);
        return NULL;
        }

memset(&key, 0, sizeof(key));
memset(&data, 0, sizeof(data));

key.data = (char *)hostname;
key.size = strlen(hostname);

data.data=docroot;
data.size=strlen(docroot);

ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: set_db_dr: %s[%d]",key.data,key.size);

if ((ret = dbp->put(dbp, NULL, &key, &data, 0)) != 0)
        {
        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: set_db_docroot: error setting documentroot");
        };

if ((ret=dbp->close(dbp, 0))!=0)
        {
        dbp->err(dbp, ret, "DB->put");
        };

return dr;

};


#ifdef HAVE_PGSQL
static char *get_pgsql_docroot(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config   	*vc;

char                    *dr=NULL;
char                    filter[1024];
char			*val;

PGconn                  *conn;
PGresult 		*res;
int                     n;


vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]:  No hostname received by get_pgsql_dr ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: host: %s",vc->pgsql_host);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: port: %s",vc->pgsql_port);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: user: %s",vc->pgsql_user);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: pass: %s",vc->pgsql_pass);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->pgsql_db);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->pgsql_select);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: database: %s",vc->poscache);


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
                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_pgsql_dr: Connection established.");
                snprintf(filter,1024,vc->pgsql_select,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_pgsql_dr: Filter: %s",filter);
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
                                        dr=apr_palloc(r->pool,strlen(val+1));
                                        snprintf(dr,strlen(val)+1,"%s",val);
                                        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_pgsql_dr: got %s from pgsql",dr);
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

static char *get_ldap_docroot(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config       *vc;

char                    *dr=NULL;
char                    filter[1024];
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

ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: host: %s",vc->ldap_host);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: port: %s",vc->ldap_port);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: binddn: %s",vc->ldap_binddn);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: bindpw: %s",vc->ldap_bindpw);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: basedn: %s",vc->ldap_basedn);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: filter: %s",vc->ldap_filter);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "mod_vhost.c: CONF: database: %s",vc->poscache);

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
                snprintf(filter,1024,vc->ldap_filter,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"mod_vhost.c: get_ldap_dr: Filter: %s",filter);
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
                                        snprintf(dr,strlen(val[0])+1,"%s",val[0]);
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

static char *get_mysql_docroot(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config        *vc;

char                    *dr=NULL;
char                    filter[1024];
char                    *val;
int                     n;

MYSQL			*conn;
MYSQL_RES		*res;
MYSQL_ROW		row;



vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]:  get_mysql_docroot: No hostname received ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: host: %s",vc->mysql_host);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: port: %s",vc->mysql_port);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: user: %s",vc->mysql_user);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: pass: %s",vc->mysql_pass);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->mysql_db);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->mysql_select);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: database: %s",vc->poscache);


if (vc->mysql_host==NULL ||
        vc->mysql_port==NULL ||
        vc->mysql_user==NULL ||
        vc->mysql_pass==NULL ||
        vc->mysql_db==NULL ||
        vc->mysql_select==NULL )
        {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_docroot: Dont have all needed Mysql Settings");
} else {

        conn=mysql_connct(vc);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_docroot: cant connect to SQL server");
        } else {
                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_mysql_docroot: connection established.");
                snprintf(filter,1024,vc->mysql_select,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_mysql_docroot: select: %s",filter);
                res=mysql_tuples(conn,filter);

                if (res==NULL) {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_mysql_docroot: search error");
                } else {
                        n=mysql_num_fields(res);

                        if (n!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"[mod_vhost.c]: get_mysql_docroot no single entry for query: %s",filter);
                        } else {
				row=mysql_fetch_row(res);
				if (row!=NULL) {
                                	val=row[0];
                                	if (val!=NULL && strlen(val)>0) {
                                        	dr=apr_palloc(r->pool,strlen(val+1));
                                        	snprintf(dr,strlen(val)+1,"%s",val);
                                        	ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_mysql_docroot: got %s from mysql",dr);
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
static char *get_sqlite_docroot(server_rec *s,request_rec *r,char *hostname)
{
mod_vhost_config        *vc;

char                    *dr=NULL;
char                    filter[1024];
char                    *val;
int                     n;

sqlite3			 *conn;
char			*wynik[8];
int			cnt=0;
int			rc;



vc=ap_get_module_config(r->server->module_config, &mod_vhost_module);

if (r->hostname==NULL) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]:  get_sqlite_docroot: No hostname received ");
        return NULL;
        };

ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: db: %s",vc->sqlite_db);
ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,s, "[mod_vhost.c]: CONF: select: %s",vc->sqlite_select);


if (vc->sqlite_db==NULL || vc->sqlite_select==NULL) {
        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_docroot: Dont have all needed Sqlite Settings");
} else {

        conn=sqlite_connect(vc);

        if (conn==NULL)
                {
                ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_docroot: cant connect to SQLte server");
        } else {
                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_sqlite_docroot: connection established.");
                snprintf(filter,1024,vc->sqlite_select,r->hostname);

                ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_sqlite_docroot: select: %s",filter);
                rc=sqlite_tuples(s,conn,filter,(char ***)&wynik,&cnt);


                if (rc<0) {
                        ap_log_error(APLOG_MARK,APLOG_CRIT,0,s,"[mod_vhost.c]: get_sqlite_docroot: search error");
                } else {
                        if (cnt!=1) {
                                ap_log_error(APLOG_MARK,APLOG_ERR,0,s,"[mod_vhost.c]: get_sqlite_docroot no single entry for query: [%s], got %d",filter,cnt);
                        } else {
                                val=wynik[0];
                                if (val!=NULL && strlen(val)>0) {
                                        dr=apr_palloc(r->pool,strlen(val+1));
                                        snprintf(dr,strlen(val)+1,"%s",val);
                                        ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: get_sqlite_docroot: got %s from sqlite",dr);
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

static char		*documentroot=NULL;
static char		*dr=NULL;
char			filter[1024];



if (vc->enable==0) {
	return DECLINED;
	};


s=r->server;

if ((char *)r->hostname==NULL || strlen(r->hostname)==0 )
	{
	ap_log_error(APLOG_MARK, APLOG_ERR, 0,s, "[mod_vhost.c]: No Hostname recived by trans_uri");
	return DECLINED;
	};

ap_log_error(APLOG_MARK, APLOG_DEBUG,0,s,"Received: [%s]",r->hostname);

if ((documentroot=check_alias(r,vc->aliases))!=NULL) {

	ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c]: Got Alias [%s]->[%s]",r->uri,documentroot);

//        r->server->server_admin= apr_pstrcat(r->pool,"webmaster@",r->hostname,NULL);
//        r->server->server_hostname= apr_pstrcat(r->pool,r->hostname,NULL);

//        r->parsed_uri.path=apr_pstrcat(r->pool,documentroot,r->parsed_uri.path,NULL);
//        r->parsed_uri.hostname=r->server->server_hostname;
//        r->parsed_uri.hostinfo=r->server->server_hostname;

        r->filename=apr_pstrcat(r->pool,vc->dir,documentroot,NULL);

	return OK;

	};


if (vc->negcache!=NULL) {
	documentroot=get_db_docroot(r->server,r,(char *)r->hostname,vc->negcache);
	if (documentroot!=NULL && !strcmp(documentroot,"NOT_FOUND")) {
		ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"mod_vhost: hostname [%s] found in negative Cache",(char *)r->hostname);
		return DECLINED;
		};
	} ;

if (vc->poscache!=NULL) {
	documentroot=get_db_docroot(r->server,r,(char *)r->hostname,vc->poscache);
	if (documentroot==NULL) {
		#ifdef HAVE_PGSQL
		dr=get_pgsql_docroot(r->server,r,(char *)r->hostname);
		#endif
		#ifdef HAVE_LDAP
		dr=get_ldap_docroot(r->server,r,(char *)r->hostname);
		#endif
		#ifdef HAVE_MYSQL
		dr=get_mysql_docroot(r->server,r,(char *)r->hostname);
		#endif
		#ifdef HAVE_SQLITE
		dr=get_sqlite_docroot(r->server,r,(char *)r->hostname);
		#endif
		if (dr==NULL) {
			ap_log_error(APLOG_MARK,APLOG_WARNING,0,s,"[mod_vhost.c]: hostname not found in database [%s]",(char *)r->hostname);
			documentroot=NULL;
			} else {
			set_db_docroot(r->server,r,(char *)r->hostname,dr,vc->poscache);
			documentroot=apr_pstrdup(r->pool,dr);
			};
		};

	if (documentroot==NULL) {
		set_db_docroot(r->server,r,(char *)r->hostname,"NOT_FOUND",vc->negcache);
		return DECLINED;
		};

	if (vc->debug>0) {
		ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"[mod_vhost.c] documentroot: [%s][%d]",documentroot,strlen(documentroot));
		};

	documentroot[strlen(documentroot)]='\0';

/*
	r->server->server_admin= apr_pstrcat(r->pool,"webmaster@",r->hostname,NULL);
	r->server->server_hostname= apr_pstrcat(r->pool,r->hostname,NULL);

	r->parsed_uri.path=apr_pstrcat(r->pool,documentroot,r->parsed_uri.path,NULL);
	r->parsed_uri.hostname=r->server->server_hostname;
	r->parsed_uri.hostinfo=r->server->server_hostname;
*/

	r->server->server_hostname = apr_pstrdup(r->pool, r->hostname); // prepare server hostname
//	r->server->is_virtual = 1;
//	r->parsed_uri.hostinfo = r->server->server_hostname;
//	r->parsed_uri.hostname = r->server->server_hostname;

	r->filename=apr_pstrcat(r->pool,vc->dir,documentroot,r->uri,NULL);
	ap_no2slash(r->filename);

	ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"Server Name [%s]",r->server->server_hostname);
	ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"Filename [%s]",r->filename);
	ap_log_error(APLOG_MARK,APLOG_DEBUG,0,s,"URI [%s]",r->uri);

	snprintf(filter,1024,"%s%s",vc->dir,documentroot);
	ap_no2slash(filter);
	apr_table_setn(r->subprocess_env, "SERVER_ROOT", apr_pstrdup(r->pool,filter));
	apr_table_set(r->subprocess_env, "DOCUMENT_ROOT", apr_pstrdup(r->pool,filter));
	apr_table_setn(r->subprocess_env, "PHP_DOCUMENT_ROOT", apr_pstrdup(r->pool,filter));
	//scfg->ap_document_root = apr_pstrdup(r->pool,filter);


#ifdef HAVE_PHP
	if (zend_alter_ini_entry("open_basedir", sizeof("open_basedir"), filter, strlen(filter), 4, 1) < 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0,s,"zend_alter_ini_entry() set open_basedir failed");
		};
	if (zend_alter_ini_entry("doc_root", sizeof("doc_root"), filter, strlen(filter), 4, 1) < 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0,s, "zend_alter_ini_entry() set doc_root failed");
		};

	snprintf(filter,1024,"%s%s/tmp",vc->dir,documentroot);
	ap_no2slash(filter);
	if (zend_alter_ini_entry("session.save_path", sizeof("session.save_path"), filter, strlen(filter), 4, 1) < 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0,s, "zend_alter_ini_entry() set doc_root failed");
		};
	if (zend_alter_ini_entry("upload_tmp_dir", sizeof("upload_tmp_dir"), filter, strlen(filter), 4, 1) < 0) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING, 0,s, "zend_alter_ini_entry() set doc_root failed");
		};
#endif
	return OK;
	} else {
	return DECLINED;
	};

return DECLINED;
};


/***** config *****/

static void *mod_vhost_create_cfg(apr_pool_t *p, server_rec * s)
{
mod_vhost_config *vc;

vc= (mod_vhost_config *) apr_pcalloc(p,sizeof(mod_vhost_config));

vc->dir="/www";
vc->poscache="/tmp/positive.db";
vc->negcache="/tmp/negative.db";
vc->minuid=1000;
vc->mingid=1000;
#ifdef HAVE_PGSQL
vc->pgsql_host="localhost";
vc->pgsql_port="5432";
vc->pgsql_user=NULL;
vc->pgsql_pass=NULL;
vc->pgsql_db=NULL;
vc->pgsql_select="select documentroot from www where domainname=%s";
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
vc->mysql_select="select documentroot from www where domainname=%s";
#endif
#ifdef HAVE_SQLITE
vc->sqlite_db="/tmp/baza.db";
vc->sqlite_select="select documentroot from www where domainname=%s";
#endif

vc->debug="0";

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







/***** config *****/

static void mod_vhost_register_hooks(apr_pool_t *p) {
//	static const char * const vhSucc[]={ "mod_alias.c", NULL };
        ap_hook_translate_name(mod_vhost_trans_uri, NULL, NULL, APR_HOOK_MIDDLE);
};


static const command_rec mod_vhost_cmds[] = {
	AP_INIT_TAKE1("ModVhostEnable",(void *)mod_vhost_set_enable, NULL, RSRC_CONF, "Set on or off to disable mod_vhost"),
	AP_INIT_TAKE2("ModVhostServer",(void *)mod_vhost_set_server, NULL, RSRC_CONF, "Set Server used for connection"),
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

