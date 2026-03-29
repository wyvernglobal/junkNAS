cmake_minimum_required(VERSION 3.20)
project(JunkNAS-GUI CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)

set(GUI_SOURCES
    main_gui.cpp
    main_window.cpp
    main_window.h
    sidebar_widget.cpp
    sidebar_widget.h
    dashboard_page.cpp
    dashboard_page.h
    addnode_page.cpp
    addnode_page.h
    joincloud_page.cpp
    joincloud_page.h
    peers_page.cpp
    peers_page.h
    settings_page.cpp
    settings_page.h
    api_client.h
)

qt_add_executable(junknas-gui ${GUI_SOURCES})

target_link_libraries(junknas-gui PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
)

target_include_directories(junknas-gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Install alongside the Go daemon binary.
install(TARGETS junknas-gui
    RUNTIME DESTINATION bin
)
