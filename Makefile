# Tetherand top-level orchestration. POSIX-compatible.
.PHONY: all build relay apk native-wg native-tor native-nym native-pt native-rtlsdr native-all install uninstall clean test smoke smoke-device release release-signed hashes chain launcher

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

native-wg:
	bash scripts/build-wg-android.sh

native-tor:
	bash scripts/build-tor-android.sh

native-nym:
	bash scripts/build-nym-android.sh

native-pt:
	bash scripts/build-pt-bridge-android.sh
	bash scripts/build-pts-android.sh

native-rtlsdr:
	bash scripts/build-rtlsdr-android.sh

native-all: native-wg native-tor native-nym native-pt native-rtlsdr
	@echo "  ✓ all native libs cross-compiled into jniLibs/arm64-v8a/"

launcher:
	bash scripts/install-launchagent.sh

apk: native-wg
	cd $(ANDROID) && ./gradlew :app:assembleDebug
	@mkdir -p $(BIN)
	@cp $(ANDROID)/app/build/outputs/apk/debug/app-debug.apk $(BIN)/tetherand.apk
	@bash scripts/hash-artifacts.sh
	@echo "  ✓ APK built at $(BIN)/tetherand.apk (+ SHA-256/SHA3-256 sidecars)"

chain: build
	@echo "Chain build complete. Open Tetherand → Privacy tab to configure."

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

smoke-device: install
	bash scripts/smoke-device.sh

release-signed:
	bash scripts/release-sign.sh

# Emit SHA-256 + SHA3-256 hashes for every artefact in bin/.
hashes:
	bash scripts/hash-artifacts.sh

clean:
	cd $(RELAY)   && cargo clean
	cd $(ANDROID) && ./gradlew clean
	rm -f $(BIN)/tetherand $(BIN)/tetherand.apk $(BIN)/tetherand-release.apk
