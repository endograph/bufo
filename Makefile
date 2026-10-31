.PHONY: build test

# Signed bufo in .build/bufo-signed (scripts/build.sh).
build:
	scripts/build.sh

test:
	swift test
