set(TEST_APP_SOURCES
    testapp/curl_network_transport.cpp
    testapp/main.cpp
    testapp/test_data.cpp
) # TEST_APP_SOURCES

set(TEST_APP_HEADERS
    testapp/generic_network_transport.hpp
    testapp/test_data.hpp
) # TEST_APP_HEADERS


add_executable(testapp)
target_sources(testapp PRIVATE ${TEST_APP_SOURCES} ${TEST_APP_HEADERS})
target_include_directories(testapp PUBLIC .)
target_compile_definitions(testapp PUBLIC REALM_ENABLE_SYNC=1)
target_link_libraries(testapp PUBLIC Realm::ObjectStore)

find_package(CURL REQUIRED)
target_link_libraries(testapp PUBLIC CURL::libcurl)
