SJCL_PATH=node_modules/sjcl

all:
	cd ${SJCL_PATH} && \
	./configure --without-all --with-ecc --with-convenience --compress=none \
            --with-codecBytes --with-codecHex --with-codecArrayBuffer && \
	make
	npm i -D dts-gen
	npx dts-gen -m sjcl -o -f ./src/sjcl/index
	npm un -D dts-gen
	echo "export default sjcl;" >> ${SJCL_PATH}/sjcl.js
	cp ${SJCL_PATH}/sjcl.js ./src/sjcl/index.js
	patch src/sjcl/index.d.ts sjcl.point.patch

clean:
	rm -f src/sjcl/index.js src/sjcl/index.d.ts
