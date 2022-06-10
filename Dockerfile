ROM fuzzers/libfuzzer:12.0

#RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key| apt-key add -
RUN apt-get update
RUN apt install -y build-essential wget git xz-utils automake autotools-dev  libtool zlib1g zlib1g-dev libssl-dev curl
RUN wget https://github.com/Kitware/CMake/releases/download/v3.20.1/cmake-3.20.1.tar.gz
RUN tar xvfz cmake-3.20.1.tar.gz
WORKDIR /cmake-3.20.1
RUN ./bootstrap
RUN make
RUN make install
RUN printf "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-12 main" | tee /etc/apt/sources.list.d/llvm-toolchain-xenial-12.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update
RUN apt install -y llvm-12 clang-12
WORKDIR /
RUN git clone --recursive https://github.com/ethereum/evmone
WORKDIR /evmone
RUN cmake -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DBUILD_SHARED_LIBS=false -DEVMONE_FUZZING=ON .
RUN make
RUN make install

ENTRYPOINT []
CMD /evmone/bin/evmone-fuzzer
