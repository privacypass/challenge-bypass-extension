SOURCES= src/ext/requires.js         \
		 src/crypto/keccak/keccak.js \
		 src/crypto/local.js         \
		 src/ext/background.js       \
		 src/ext/browserUtils.js     \
		 src/ext/config.js           \
		 src/ext/h2c.js              \
		 src/ext/issuance.js         \
		 src/ext/redemption.js       \
		 src/ext/tokens.js           \
		 src/ext/utils.js
LISTENER=src/ext/listeners.js
SJCL_PATH=src/crypto/sjcl

all: build
.PHONY: build
build: addon/build.js

.PHONY: test
test: test-ext

.PHONY: test-all
test-all: test-sjcl test-ext

.PHONY: test-ext
test-ext: jest/globals.js addon/test.js
	yarn test

.PHONY: test-sjcl
test-sjcl:
	make test -C ${SJCL_PATH}

.PHONY: install
install:
	yarn install

.PHONY: lint
lint: build
	yarn lint

.PHONY: dist
dist: build
	mkdir -p ./dist
	cp -a addon/* ./dist/
	zip ext.zip ./dist
	rm -rf ./dist

addon/build.js: ${SJCL_PATH}/sjcl.js ${SOURCES} ${LISTENER}
	cat $^ > $@
addon/test.js: ${SJCL_PATH}/sjcl.js ${SOURCES}
	cat $^ > $@
${SJCL_PATH}/sjcl.js:
	git submodule update --init
	cd ${SJCL_PATH}; ./configure --without-all --with-ecc --with-convenience \
	--with-codecBytes --with-codecHex --compress=none
	make -C ${SJCL_PATH} sjcl.js

clean:
	rm -f ${SJCL_PATH}/sjcl.js addon/build.js addon/test.js ext.zip

dist-clean: clean
	rm -rf ./node_modules
