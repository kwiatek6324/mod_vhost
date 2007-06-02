##
##  Makefile -- Build procedure for sample vhost_mysql Apache module
##  Autogenerated via ``apxs -n vhost_mysql -g''.
##

BACKEND=-DHAVE_PGSQL -DHAVE_PHP

#   the used tools
APXS=/opt/idsl/httpd/bin/apxs
APACHECTL=/opt/idsl/httpd/bin/apache2ctl
LIBS= -ldb-4.4 -L/usr/local/lib/ -lpq -I/opt/idsl/pgsql/include/ -L/opt/idsl/pgsql/lib $(BACKEND)

#   additional user defines, includes and libraries

#   the default target
all: mod_vhost.so

#   compile the DSO file
mod_vhost.so: mod_vhost.c
	$(APXS) -c $(LIBS) mod_vhost.c

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: 
	$(APXS) -aic $(LIBS) mod_vhost.c

#   cleanup
clean:
	rm -f mod_vhost.o mod_vhost.so
	rm -rf .libs
	rm -f *.la *.lo *.slo

#   reload the module by installing and restarting Apache
reload: install restart

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

