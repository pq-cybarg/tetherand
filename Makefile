# Tetherand top-level orchestration. POSIX-compatible.
.PHONY: all build relay apk install uninstall clean test smoke release

REPO    := $(shell pwd)
RELAY   := $(REPO)/relay
ANDROID := $(REPO)/android
BIN     := $(REPO)/bin

all: build

build: relay apk

relay:
	cd $(RELAY) && cargo build --release -p tetherand-cli
	@mkdir -p $(BIN)
	@cp $(RELAY)/target/release/tetherand $(BIN)/tetherand
	@echo "  ✓ relay built at $(BIN)/tetherand"

apk:
	cd $(ANDROID) && ./gradlew :app:assembleDebug
	@mkdir -p $(BIN)
	@cp $(ANDROID)/app/build/outputs/apk/debug/app-debug.apk $(BIN)/tetherand.apk
	@echo "  ✓ APK built at $(BIN)/tetherand.apk"

# Release variant of the APK. Uses the debug signing config (the spec
# defers a real production-signing key to M8).
release: relay
	cd $(ANDROID) && ./gradlew :app:assembleRelease
	@mkdir -p $(BIN)
	@cp $(ANDROID)/app/build/outputs/apk/release/app-release*.apk $(BIN)/tetherand-release.apk
	@echo "  ✓ release APK at $(BIN)/tetherand-release.apk"

install: apk
	@which adb >/dev/null || (echo "adb required"; exit 1)
	adb install -r $(BIN)/tetherand.apk
	adb shell cmd appops set dev.tetherand.app ACTIVATE_VPN allow
	@echo "  ✓ APK installed and VPN consent pre-granted"

uninstall:
	-adb uninstall dev.tetherand.app
	-adb uninstall com.genymobile.gnirehtet
	@echo "  ✓ uninstalled both tetherand and the upstream gnirehtet stopgap"

test:
	cd $(RELAY) && cargo test --workspace

smoke: build install
	bash scripts/smoke.sh

clean:
	cd $(RELAY)   && cargo clean
	cd $(ANDROID) && ./gradlew clean
	rm -f $(BIN)/tetherand $(BIN)/tetherand.apk $(BIN)/tetherand-release.apk
