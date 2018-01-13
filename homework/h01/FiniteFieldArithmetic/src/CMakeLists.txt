file(GLOB_RECURSE FiniteFieldArithmetic_SOURCES "*.cpp")
file(GLOB_RECURSE FiniteFieldArithmetic_HEADERS "*.h")

set (FiniteFieldArithmetic_INCLUDE_DIRS "")
foreach (_headerFile ${FiniteFieldArithmetic_HEADERS})
    get_filename_component(_dir ${_headerFile} PATH)
    list (APPEND FiniteFieldArithmetic_INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES FiniteFieldArithmetic_INCLUDE_DIRS)

add_executable (FiniteFieldArithmetic ${FiniteFieldArithmetic_SOURCES})
target_include_directories(FiniteFieldArithmetic PRIVATE ${FiniteFieldArithmetic_INCLUDE_DIRS})

target_link_libraries(FiniteFieldArithmetic)