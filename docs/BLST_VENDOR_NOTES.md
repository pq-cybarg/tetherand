# Vendored blst — Cross-Compile Procedure

[Supranational's blst](https://github.com/supranational/blst) is the
audited BLS12-381 implementation we use for drand-quicknet round
verification. We vendor it locally rather than depending on a Maven
artifact for two reasons:

1. **Audit pedigree.** blst has had multiple public security audits
   (Trail of Bits, NCC Group, Quarkslab) and is what drand-go's own
   reference client uses. Maven repositories of Java BLS12-381 are
   either unaudited (Apache Milagro) or stale wrappers around blst
   anyway.
2. **Native code.** blst is C + assembly. We cross-compile per ABI
   for Android and ship the `.so` directly in `jniLibs/`. No
   surprise at runtime; what you build is what installs.

## Pinned commit

The current vendored copy is built from the `HEAD` of
`https://github.com/supranational/blst` as of 2026-06-01. If
upstream advances, re-run the procedure below to update.

## Cross-compile procedure (macOS host, Android NDK 26.3)

```sh
# 1. Clone
cd /tmp && rm -rf blst
git clone --depth=1 https://github.com/supranational/blst.git
cd blst

# 2. arm64-v8a (Solana 5364C13D + Android-15 ARM64 emulator)
NDK=$HOME/Library/Android/sdk/ndk/26.3.11579264
TC=$NDK/toolchains/llvm/prebuilt/darwin-x86_64
export CC=$TC/bin/aarch64-linux-android21-clang
export AR=$TC/bin/llvm-ar
./build.sh                                    # produces libblst.a

# 3. SWIG-generate the Java bindings
cd bindings/java
mkdir -p supranational
swig -c++ -java -package supranational.blst -outdir supranational \
     -o blst_wrap.cpp ../blst.swg

# 4. JNI wrapper .so for arm64-v8a
CXX=$TC/bin/aarch64-linux-android21-clang++
$CXX -std=c++11 -shared -fPIC -fvisibility=hidden \
     -I.. -I/tmp/blst -O2 -Wall -Wno-unused-function \
     -o libblst.so blst_wrap.cpp /tmp/blst/libblst.a \
     -Wl,-Bsymbolic

# 5. Repeat 2 + 4 for x86_64 (emulator hosts that aren't arm64)
cd /tmp/blst && rm -f *.o libblst.a
export CC=$TC/bin/x86_64-linux-android21-clang
./build.sh
mv libblst.a libblst-x86_64.a
cd bindings/java
CXX=$TC/bin/x86_64-linux-android21-clang++
$CXX -std=c++11 -shared -fPIC -fvisibility=hidden \
     -I.. -I/tmp/blst -O2 -Wall -Wno-unused-function \
     -o libblst-x86_64.so blst_wrap.cpp /tmp/blst/libblst-x86_64.a \
     -Wl,-Bsymbolic
```

## Vendoring into the project

```sh
TETHERAND=/path/to/reverse-tethering
mkdir -p $TETHERAND/android/app/src/main/jniLibs/{arm64-v8a,x86_64}
cp /tmp/blst/bindings/java/libblst.so        $TETHERAND/android/app/src/main/jniLibs/arm64-v8a/libblst.so
cp /tmp/blst/bindings/java/libblst-x86_64.so $TETHERAND/android/app/src/main/jniLibs/x86_64/libblst.so

# blst dynamically links libc++. Ship the matching NDK STL too:
cp $NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so \
   $TETHERAND/android/app/src/main/jniLibs/arm64-v8a/libc++_shared.so
cp $NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so \
   $TETHERAND/android/app/src/main/jniLibs/x86_64/libc++_shared.so

# SWIG-generated Java bindings
mkdir -p $TETHERAND/android/app/src/main/java/supranational/blst
cp /tmp/blst/bindings/java/supranational/*.java \
   $TETHERAND/android/app/src/main/java/supranational/blst/
```

## What the vendored set looks like

```
android/app/src/main/
├── java/supranational/blst/
│   ├── BLST_ERROR.java     # error-code enum
│   ├── P1.java + P1_Affine.java  # G1 element types
│   ├── P2.java + P2_Affine.java  # G2 element types
│   ├── PT.java                   # GT (target group)
│   ├── Pairing.java              # high-level pairing context
│   ├── Scalar.java + SecretKey.java
│   ├── blst.java + blstJNI.java  # SWIG glue
└── jniLibs/
    ├── arm64-v8a/
    │   ├── libblst.so        (~330 KB, blst + JNI)
    │   └── libc++_shared.so  (~1.8 MB, NDK STL)
    └── x86_64/
        ├── libblst.so        (~345 KB)
        └── libc++_shared.so  (~1.6 MB)
```

## Empirical verification

`docs/EMULATOR_PROOF_2026-05-31.md` (and the follow-up entry below it)
shows the live evidence on the Android 15 ARM64 AVD:

```
I SeekerRng: installed as JCA default (SHAKE-256 mixer over 8 sources)
I PublicBeacons: background refresher started (drand + NIST, every 60s)
D nativeloader: Load .../jniLibs/arm64-v8a/libblst.so ... ok
I PublicBeacons: drand round 29177277 BLS-verified + absorbed
                 (blst pairing check passed)
```

That `BLS-verified + absorbed` line is `DrandVerifier.verify()` →
`Pairing.aggregate(P2_Affine pk, P1_Affine sig, msg, aug)` →
`Pairing.commit()` → `Pairing.finalverify()` all returning success
against a real round fetched from `api.drand.sh`.

## Threat-model fit

The verification path is on a **public-key signature** (no secret on
our side), invoked every ~60s by `PublicBeacons`. Three independent
layers gate the drand input even before blst sees it:

1. SPKI cert pin on `api.drand.sh` (system NSC + OkHttp `CertificatePinner`).
2. Tor-mandatory egress (default; user-toggleable to clear-net via
   `BeaconPolicy.clearnetFallback`).
3. `DrandVerifier.QUICKNET_PUBKEY_HEX` is pinned in-code.

A correctness failure in blst here would let a hostile drand round
absorb-as-"verified". `SeekerRng`'s SHAKE-256 mixer contains that
blast radius — the other seven sources (urandom, JCA SecureRandom,
KeyStore HMAC, sensor jitter, clock skew, NIST beacon, activity
fingerprint) carry the call. So even a blst correctness regression
degrades us only to the pre-blst baseline.
