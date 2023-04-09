
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/nginx.exe -t

	kill -USR2 `cat /logs/nginx.pid`
	sleep 1
	test -f /logs/nginx.pid.oldbin

	kill -QUIT `cat /logs/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
