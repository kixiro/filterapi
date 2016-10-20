default: build

clean:
	sudo rm -rf dist
	sudo rm -f *.spec
	sudo rm -rf bulid/filterapi_*

all: build

build: deb8 deb7 el6 el5

define compile
	docker pull $(1)
	docker build -t filterapi_$(2) -f build/Dockerfile.$(2) ./build/
	docker run -it -v $(PWD):/root/src filterapi_$(2) pyinstaller -F -s src/filterapi.py
endef

deb8:
	$(call compile,debian:jessie,deb8)

deb7:
	$(call compile,debian:wheezy,deb7)

el6:
	$(call compile,centos:6,el6)

el5:
	$(call compile,centos:5,el5)
