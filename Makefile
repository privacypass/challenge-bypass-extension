SOURCES= src/crypto/keccak/keccak.js \
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
ASN1_PATH=src/crypto/asn1
SJCL_PATH=src/crypto/sjcl

all: build
.PHONY: build
build: addon/build.js

.PHONY: sjcl
sjcl:
	cd ${SJCL_PATH}; ./configure --without-all --with-ecc --with-convenience \
	--with-codecBytes --with-codecHex --compress=none
	make -C ${SJCL_PATH} sjcl.js

.PHONY: test
test: test-ext
	yarn test

.PHONY: test-ext
test-ext: jest/globals.js addon/test.js

.PHONY: test-all
test-all: test-sjcl test

.PHONY: test-sjcl
test-sjcl:
	make test -C ${SJCL_PATH}

.PHONY: install
install:
	yarn install

.PHONY: lint
lint:
	yarn lint

.PHONY: dist
dist: build
	mkdir -p ./dist
	cp -a addon/* ./dist/
	zip -r ext.zip ./dist
	rm -rf ./dist

addon/build.js: ${ASN1_PATH}/asn1-parser.js ${SJCL_PATH}/sjcl.js ${SOURCES} ${LISTENER}
	cat $^ > $@
addon/test.js: ${ASN1_PATH}/asn1-parser.js ${SJCL_PATH}/sjcl.js ${SOURCES}
	cat $^ > $@

clean:
	rm -f ${SJCL_PATH}/sjcl.js addon/build.js addon/test.js ext.zip

dist-clean: clean
	rm -rf ./node_modules
