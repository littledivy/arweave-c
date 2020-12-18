build:
	gcc wallet.c sha256/sha256.c -I/usr/local/include -L/usr/local/lib -lcjose -ljansson -lcrypto -Wl,-R/usr/local/lib -o wallet
  
install:
	git submodule add git@github.com:cisco/cjose.git
	git submodule add git@github.com:akheron/jansson.git
	cd jansson
	autoreconf -i
	./configure
	make
	make install
	cd ../cjose
	./configure
	make

