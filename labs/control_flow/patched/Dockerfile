FROM gcc:12
WORKDIR /lab
COPY demo.c /lab/demo.c
RUN gcc -std=c11 -O0 -g -Wall -Wextra -no-pie -fno-stack-protector -DPATCHED_BUILD -o /lab/demo /lab/demo.c
USER 65534:65534
ENTRYPOINT ["/lab/demo"]
