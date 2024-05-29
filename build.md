#Build nflog for android

ndk_version=21.4.7075529

NDK="/path_to_android_sdk/Android/Sdk/ndk/${ndk_version}"
export PATH="$PATH:$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export GOPATH=/path_to_go/go/
export GOOS='android'
export CGO_ENABLED=1

#armv7a:
export GOARCH='arm'
export CC="armv7a-linux-androideabi16-clang"
export CCX="armv7a-linux-androideabi16-clang++"
export CGO_CFLAGS="-g -O3 -mfpu=neon -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CPPFLAGS="-g -O3 -mfpu=neon -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CXXFLAGS="-g -O3 -mfpu=neon -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_FFLAGS="-g -O3 -mfpu=neon -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_LDFLAGS="-g -O3 -mfpu=neon -ftree-vectorize -fvectorize -fslp-vectorize"

#arm64:
export GOARCH='arm64'
export CC="aarch64-linux-android21-clang"
export CCX="aarch64-linux-android21-clang++"
export CGO_CFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CPPFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CXXFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_FFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_LDFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"




#x86:
export GOARCH='386'
export GO386=sse2
export CC="i686-linux-android16-clang"
export CCX="i686-linux-android16-clang++"
export CGO_CFLAGS="-g -O3 -msse2 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CPPFLAGS="-g -O3 -msse2 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CXXFLAGS="-g -O3 -msse2 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_FFLAGS="-g -O3 -msse2 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_LDFLAGS="-g -O3 -msse2 -ftree-vectorize -fvectorize -fslp-vectorize"

#x86_64:
export GOARCH='amd64'
export CC="x86_64-linux-android21-clang"
export CCX="x86_64-linux-android21-clang++"
export CGO_CFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CPPFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_CXXFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_FFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"
export CGO_LDFLAGS="-g -O3 -ftree-vectorize -fvectorize -fslp-vectorize"

#common:
go clean
go build -x -ldflags="-s -w" -compiler gc -gcflags="-m -dwarf=false" -o libnflog.so
