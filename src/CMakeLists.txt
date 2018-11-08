
set(CMAKE_CXX_STANDARD 11)

add_definitions(-DCURVE=BN128)

include_directories(/usr/local/include)

link_directories(/usr/local/lib)

add_executable(sudoku sudoku_gadget.hpp
        sudoku_snark.hpp
        sudoku_snark.cpp
        main.cpp)

target_link_libraries(sudoku ff)
#target_link_libraries(sudoku fqfft)
target_link_libraries(sudoku gmpxx)
target_link_libraries(sudoku gmp)
target_link_libraries(sudoku procps)
