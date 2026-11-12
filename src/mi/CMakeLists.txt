find_package(Qt5 5.11 REQUIRED COMPONENTS Core Gui Widgets)

set(MI_SOURCES
    moneu-mi.cpp
    mainwindow.cpp
    nodehost.cpp
    rpcclient.cpp
    rpcworker.cpp
    historyscanner.cpp
    noisejob.cpp
    widgets.cpp
    dialogs.cpp
    miutil.cpp
    mi.qrc
    ${CMAKE_SOURCE_DIR}/src/main.cpp
    ${CMAKE_SOURCE_DIR}/src/miner.cpp
    ${CMAKE_SOURCE_DIR}/src/node/gpu_miner.cpp
)

if(WIN32)
    enable_language(RC)
    set(MI_ICON "${CMAKE_SOURCE_DIR}/src/app/moneu.ico")
    configure_file(res/moneu-mi-res.rc.in
                   ${CMAKE_CURRENT_BINARY_DIR}/moneu-mi-res.rc @ONLY)
    list(APPEND MI_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/moneu-mi-res.rc)
endif()

add_executable(moneu-mi WIN32 ${MI_SOURCES})

set_target_properties(moneu-mi PROPERTIES
    AUTOMOC ON
    AUTORCC ON
)

target_compile_definitions(moneu-mi PRIVATE
    MONEU_MI
    QT_NO_KEYWORDS
    MI_VERSION="${PROJECT_VERSION}"
)

target_include_directories(moneu-mi PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/crypto
    ${CMAKE_SOURCE_DIR}/src/app
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu-mi
    -Wl,--start-group
    moneu_rpc
    moneu_node
    moneu_net
    moneu_validation
    moneu_storage
    moneu_consensus
    moneu_primitives
    moneu_wallet
    moneu_crypto
    moneu_chainparams
    ${LEVELDB_LIBRARY}
    -Wl,--end-group
    Qt5::Widgets
    Qt5::Gui
    Qt5::Core
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${PLATFORM_LIBRARIES}
    Threads::Threads
    ${CMAKE_DL_LIBS}
)
