add_library(moneu_util STATIC
    lockorder.cpp
)

target_include_directories(moneu_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(moneu_util PUBLIC moneu_log)

# Deadlock detection, off by default.
#
# Costs a map lookup on every lock, so it is a development and test-suite
# option rather than something a node carrying money should run with. Turn
# on with: cmake -DMONEU_DEBUG_LOCKORDER=ON
option(MONEU_DEBUG_LOCKORDER "Detect lock-order inversions at runtime" OFF)
if(MONEU_DEBUG_LOCKORDER)
    target_compile_definitions(moneu_util PUBLIC MONEU_DEBUG_LOCKORDER)
    message(STATUS "Lock order checking: ENABLED")
endif()
