openssl_version := 3.0.15
openssl_file    := openssl-$(openssl_version).tar.gz
openssl_url     := https://github.com/openssl/openssl/releases/download/openssl-$(openssl_version)/$(openssl_file)
openssl_sha256  := 23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533

openssl: | $(WORK) $(PREFIX)
	$(call fetch,$(openssl_url),$(openssl_file),$(openssl_sha256))
	@if [ ! -f $(PREFIX)/.stamp_openssl ]; then \
	  echo "Building OpenSSL $(openssl_version) for $(HOST)"; \
	  rm -rf $(WORK)/openssl-$(openssl_version); \
	  tar xzf $(SOURCES)/$(openssl_file) -C $(WORK); \
	  cd $(WORK)/openssl-$(openssl_version) && \
	  CC=gcc-posix ./Configure mingw64 no-shared no-tests no-dso no-engine no-sock \
	      --prefix=$(PREFIX) --openssldir=$(PREFIX)/ssl --libdir=lib \
	      --cross-compile-prefix=$(HOST)- && \
	  $(MAKE) build_libs && \
	  $(MAKE) install_dev && \
	  touch $(PREFIX)/.stamp_openssl; \
	else \
	  echo "OpenSSL already built"; \
	fi
