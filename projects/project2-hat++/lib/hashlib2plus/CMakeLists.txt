file(GLOB hashlibcpp_SRC
        "*.h"
        "*.cpp"
        )

add_library(hashlibcpp
        ${hashlibcpp_SRC})