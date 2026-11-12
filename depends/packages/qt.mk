qt_version := 5.15.17
qt_file    := qtbase-everywhere-opensource-src-$(qt_version).tar.xz
qt_url     := https://download.qt.io/archive/qt/5.15/$(qt_version)/submodules/$(qt_file)
qt_sha256  := db1513cbb3f4a5bd2229f759c0839436f7fe681a800ff2bc34c4960b09e756ff

# Static qtbase for moneu-mi. Only needed for the MI build.
qt: | $(WORK) $(PREFIX)
	$(call fetch,$(qt_url),$(qt_file),$(qt_sha256))
	@if [ ! -f $(PREFIX)/.stamp_qt ]; then \
	  echo "Building Qt $(qt_version) for $(HOST), this takes a while"; \
	  rm -rf $(WORK)/qtbase-$(qt_version) $(WORK)/qtbin; \
	  mkdir -p $(WORK)/qtbase-$(qt_version) $(WORK)/qtbin; \
	  ln -s "$$(command -v $(CC))" $(WORK)/qtbin/$(HOST)-gcc; \
	  ln -s "$$(command -v $(CXX))" $(WORK)/qtbin/$(HOST)-g++; \
	  for t in ar ranlib strip nm objcopy objdump windres; do \
	    ln -s "$$(command -v $(HOST)-$$t)" $(WORK)/qtbin/$(HOST)-$$t; \
	  done; \
	  tar xJf $(SOURCES)/$(qt_file) -C $(WORK)/qtbase-$(qt_version) --strip-components=1 && \
	  cd $(WORK)/qtbase-$(qt_version) && \
	  ./configure -xplatform win32-g++ \
	      -device-option CROSS_COMPILE=$(WORK)/qtbin/$(HOST)- \
	      -prefix $(PREFIX) -opensource -confirm-license \
	      -release -static -nomake examples -nomake tests \
	      -no-opengl -no-dbus -no-icu -no-openssl -no-pkg-config \
	      -no-zstd -no-sql-odbc -no-sql-sqlite \
	      -qt-zlib -qt-pcre -qt-libpng -qt-libjpeg -qt-harfbuzz -qt-freetype && \
	  $(MAKE) && \
	  $(MAKE) install && \
	  touch $(PREFIX)/.stamp_qt; \
	else \
	  echo "Qt already built"; \
	fi
