
hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

add_executable(evmone-statetest)
target_sources(evmone-statetest PRIVATE statetest.cpp)
target_link_libraries(evmone-statetest PRIVATE evmone evmone::state nlohmann_json::nlohmann_json GTest::gtest)
