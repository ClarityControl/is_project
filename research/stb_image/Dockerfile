FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG STB_REF=608de2239da15d9635920e3e77d664d9c13189cd

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates clang git libclang-rt-18-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --filter=blob:none https://github.com/nothings/stb.git /opt/stb \
    && git -C /opt/stb fetch --depth=1 origin "${STB_REF}" \
    && git -C /opt/stb checkout --detach FETCH_HEAD \
    && git -C /opt/stb rev-parse HEAD > /opt/stb_revision

COPY fuzz_stb_image.c /opt/fuzz_stb_image.c
RUN clang -O1 -g -fno-omit-frame-pointer \
    -fsanitize=fuzzer,address,undefined \
    -I /opt/stb /opt/fuzz_stb_image.c \
    -o /opt/fuzz_stb_image \
    && printf 'stb source revision: ' \
    && cat /opt/stb_revision

WORKDIR /work
ENTRYPOINT ["/opt/fuzz_stb_image"]
