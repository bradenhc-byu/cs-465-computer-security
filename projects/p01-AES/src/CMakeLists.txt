file(GLOB_RECURSE AESCryptosystem_SOURCES "*.cpp")
file(GLOB_RECURSE AESCryptosystem_HEADERS "*.h")

set (AESCryptosystem_INCLUDE_DIRS "")
foreach (_headerFile ${AESCryptosystem_HEADERS})
    get_filename_component(_dir ${_headerFile} PATH)
    list (APPEND AESCryptosystem_INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES AESCryptosystem_INCLUDE_DIRS)

add_executable (AESCryptosystem ${AESCryptosystem_SOURCES})
target_include_directories(AESCryptosystem PRIVATE ${AESCryptosystem_INCLUDE_DIRS})

target_link_libraries(AESCryptosystem)