## Mass Virtual Hosting from Database Apache Module

mod_vhost is apache 2.4 mass hosting module.
It reads documentroot from various types of database (PostgreSQL/MySQL/LDAP/SQLite) 
and sets for given apache context.

Last version reads complex information documentroot:php_version (54,55,56,70,71,72)
and with connecting with apache fcgi module patch can direct to given php-fpm process.

## Installation

You have to set path to your apache apxs binary.
Also set CFLAGS and LDFLAGS for your backend libs.
In Makefile you have to set BACKEND for one value from:
1. -DHAVE_LDAP
1. -DHAVE_PGSQL
1. -DHAVE_MYSQL
1. -DHAVE_SQLITE


Then execute make && make install.
If you configured module, you can start apache webserver or 
type apachectl configtest to check your configuration. 


## Configuration Directives

Directive | Value | Description
--------- | ----- | -----------
ModVhostEnable| 1/0 | Enable/Disable Translating Uri
ModVhostServer| dbserver serverport | Set Database Server / Port

### For Ldap backend 
Directive | Value | Description
--------- | ----- | -----------
ModVhostBinddn | dn=.... | Bind DN for Ldap Server
ModVhostBindpw | xxxxxx | Bind Password
ModVhostBasedn | o=org | Base DNS for lookup
ModVhostFilter | (&(domainname=%s)) | Filter for LDAP lookup
### For PgSQL/MySQL backend 
Directive | Value | Description
--------- | ----- | -----------
ModVhostUser | websrv | User for SQL Database
ModVhostPass | has01a | Password for SQL Database
ModVhostDb | hosting | SQL Database
ModVhostSelect | select documentroot from sites where domain='%s' | SQL query for looking documentroot or documentroot:php_version string
### For SQLite backend
Directive | Value | Description
--------- | ----- | -----------
ModVhostDb | /tmp/sqlite.db | Path for SQLite database
ModVhostSelect | select documentroot from sites where domain='%s' | SQL query for looking documentroot or documentroot:php_version string

Directive | Value | Description
--------- | ----- | -----------
ModVhostDebug | 127.0.0.1 | Set IP for module Debug
ModVhostRootDir | /web | Adds Prefix for Documentroot
ModVhostPositiveCache | pos | Identifier to mark OPCache Entries for positives
ModVhostNegativeCache | neg | Identifier to mark OPCache Entries for nogatives
ModVhostAlias | /fake /real | Can alias uri for path
ModVhostSOCache | memcache:127.0.0.1:11211 | Define for Apache SOCache
ModVhostSOCacheTimeout | 120 | Timeout in seconds to keep entry in cache

### Real Example

```
ModVhostSOCache memcache:127.0.0.1:11211

<VirtualHost 127.0.0.1:8080>
ServerName virtual.local

ModVhostEnable 1
ModVhostPositiveCache pos
ModVhostNegativeCache neg
ModVhostServer 192.168.1.100 5432
ModVhostUser apacheuser
ModVhostPass apachepass
ModVhostDb hosting
ModVhostSelect "SELECT conf from getwebconf('%s')"
ModVhostRootDir /
ModVHostDebug 127.0.0.1
ModVhostSOCacheTimeout 120
ModVhostAlias /webmail /www/webmail/

ErrorLog logs/vhost_error.log
CustomLog logs/vhost_access.log combined

</VirtualHost>
```
