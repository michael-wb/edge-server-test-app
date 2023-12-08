# edge-server-test-app
Test App to test switching between cloud and edge server

To build:
* `cmake -B build -DCMAKE_BUILD_TYPE=Debug -G Ninja1`
* `cmake --build build --config Debug`

To run test app:
* Set up an edge server on `http://localhost:80`
* `cd build/src`
* `./testapp`
