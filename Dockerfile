FROM fuzzers/libfuzzer:12.0

RUN apt-get update
RUN apt install -y build-essential wget git clang  automake autotools-dev  libtool zlib1g zlib1g-dev cmake
RUN git clone --recursive https://github.com/ethereum/evmone
WORKDIR /evmone
RUN cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CC_COMPILER=clang -DBUILD_SHARED_LIBS=false -DEVMONE_FUZZING=ON .
RUN make
RUN make install

ENTRYPOINT []
CMD /evmone/bin/evmone-fuzzer
