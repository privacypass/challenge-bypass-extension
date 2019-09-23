.PHONY: install
install:
	yarn \
	&& yarn install

.PHONY: lint
lint:
	yarn lint

.PHONY: build-sjcl
build-sjcl:
	cd src/crypto/sjcl && ./configure --without-all --with-ecc --with-convenience --with-codecBytes --with-codecHex --compress=none && make sjcl.js

.PHONY: build.js
build.js: src/ext/utils.js src/crypto/sjcl/sjcl.js src/ext/config.js src/ext/h2c.js src/crypto/local.js src/ext/tokens.js src/ext/issuance.js src/ext/redemption.js src/ext/browserUtils.js src/ext/background.js src/ext/listeners.js src/crypto/keccak/keccak.js
	cat $^ > addon/$@

.PHONY: build
build: build-sjcl build.js

.PHONY: build-quick
build: build.js

.PHONY: dist
dist: build
	mkdir -p ./dist && cp -a addon/* ./dist/ && rm -rf ./dist/scripts && bestzip ext.zip ./dist && rm -rf ./dist

.PHONY: test-sjcl
test-sjcl:
	make test -C src/crypto/sjcl

.PHONY: test-build.js
test-build.js: src/ext/utils.js src/crypto/sjcl/sjcl.js src/ext/config.js src/ext/h2c.js src/crypto/local.js src/ext/tokens.js src/ext/issuance.js src/ext/redemption.js src/ext/browserUtils.js src/ext/background.js src/crypto/keccak/keccak.js
	cat $^ > addon/$@

.PHONY: test-ext
test-ext: test-build.js
	yarn test:ext-quick

.PHONY: test
test: test-sjcl test-ext