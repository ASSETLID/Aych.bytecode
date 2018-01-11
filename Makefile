DEST_DIR ?= ${CURDIR}/www

all: build test

build: _obuild
	ocp-build build

install: _obuild
	ocp-build install

_obuild: Makefile
	ocp-build init

clean: _obuild
	ocp-build clean
	-rm -rf ${DEST_DIR}
	-find -name \*~ -delete

distclean: clean
	rm -rf _obuild

test: build
	mkdir -p ${DEST_DIR}
	cp static/* ${DEST_DIR}
	cat static/pre.js _obuild/test-sodium/test-sodium.js static/post.js > ${DEST_DIR}/test-sodium.js
