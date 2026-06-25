# build stage: compile the c++23 collector with gcc-14, cmake, and libpq (for libpqxx)
FROM gcc:14 AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake git ca-certificates libpq-dev libcurl4-openssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# copy only what cmake needs so unrelated edits don't bust the layer cache
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --target node_monitor -j

# runtime stage: matching gcc-14 base so libstdc++.so.6 has the c++23 <print> symbols; libpq5 satisfies libpqxx
FROM gcc:14

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 libcurl4 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/node_monitor /usr/local/bin/node_monitor

EXPOSE 8000/tcp
EXPOSE 2055/udp

ENTRYPOINT ["/usr/local/bin/node_monitor"]
