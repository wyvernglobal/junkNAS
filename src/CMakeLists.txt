cmake_minimum_required(VERSION 3.20)
project(JunkNAS VERSION 0.1.0)

# ── Options ────────────────────────────────────────────────────────────────
option(BUILD_GUI    "Build the Qt6 GUI frontend"  ON)
option(BUILD_DAEMON "Build the Go daemon"          ON)

# ── Runtime dependency checks ─────────────────────────────────────────────
# i2pd is a runtime dependency (subprocess), not a build dependency.
# We check for it here to give a clear error at configure time on dev machines.
find_program(I2PD_EXECUTABLE i2pd
    HINTS /usr/sbin /usr/local/sbin /usr/bin /usr/local/bin /opt/i2pd
    DOC "i2pd router binary (runtime dependency)"
)
if(NOT I2PD_EXECUTABLE)
    message(WARNING
        "i2pd not found in PATH or standard locations.\n"
        "Install with:  apt install i2pd   OR   pacman -S i2pd\n"
        "JunkNAS will fail at runtime without it."
    )
else()
    message(STATUS "Found i2pd: ${I2PD_EXECUTABLE}")
endif()

find_program(SMBD_EXECUTABLE smbd DOC "Samba daemon")
if(NOT SMBD_EXECUTABLE)
    message(WARNING "smbd not found — storage nodes require Samba.")
endif()

find_program(MERGERFS_EXECUTABLE mergerfs DOC "mergerfs union filesystem")
if(NOT MERGERFS_EXECUTABLE)
    message(WARNING "mergerfs not found — required for the union mount.")
endif()

find_program(MOUNT_CIFS_EXECUTABLE mount.cifs DOC "CIFS mount helper")
if(NOT MOUNT_CIFS_EXECUTABLE)
    message(WARNING "mount.cifs not found (cifs-utils) — required for peer SMB mounts.")
endif()

# ── Go daemon ──────────────────────────────────────────────────────────────
if(BUILD_DAEMON)
    find_program(GO_EXECUTABLE go REQUIRED)
    message(STATUS "Found go: ${GO_EXECUTABLE}")

    set(DAEMON_OUTPUT ${CMAKE_BINARY_DIR}/junknasd)

    # go mod tidy resolves and verifies all dependencies, writing the real
    # go.sum. This must run before the build so checksums are correct.
    add_custom_target(junknas_tidy
        COMMAND ${GO_EXECUTABLE} mod tidy
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running go mod tidy..."
        VERBATIM
    )

    add_custom_target(junknas_daemon ALL
        COMMAND ${GO_EXECUTABLE} build
            -ldflags "-X main.Version=${PROJECT_VERSION}"
            -o ${DAEMON_OUTPUT}
            ./cmd/junknas
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Building JunkNAS daemon (Go)..."
        VERBATIM
    )

    add_dependencies(junknas_daemon junknas_tidy)

    install(PROGRAMS ${DAEMON_OUTPUT} DESTINATION bin RENAME junknasd)
endif()

# ── Qt6 GUI ────────────────────────────────────────────────────────────────
if(BUILD_GUI)
    find_package(Qt6 QUIET COMPONENTS Core Widgets Network)
    if(Qt6_FOUND)
        add_subdirectory(gui)
        message(STATUS "Qt6 found — GUI will be built")
    else()
        message(WARNING "Qt6 not found — building daemon only (headless/TUI mode)")
    endif()
endif()

# ── Systemd service ────────────────────────────────────────────────────────
configure_file(
    ${CMAKE_SOURCE_DIR}/dist/junknas.service.in
    ${CMAKE_BINARY_DIR}/junknas.service
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/junknas.service
    DESTINATION lib/systemd/system
    OPTIONAL
)
configure_file(
    ${CMAKE_SOURCE_DIR}/dist/i2pd.service.in
    ${CMAKE_BINARY_DIR}/i2pd.service
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/i2pd.service
    DESTINATION lib/systemd/system
    OPTIONAL
)

# ── Summary ────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "JunkNAS ${PROJECT_VERSION} configuration:")
message(STATUS "  Go daemon:   ${BUILD_DAEMON}")
message(STATUS "  Qt6 GUI:     ${Qt6_FOUND}")
message(STATUS "  i2pd:        ${I2PD_EXECUTABLE}")
message(STATUS "  smbd:        ${SMBD_EXECUTABLE}")
message(STATUS "  mergerfs:    ${MERGERFS_EXECUTABLE}")
message(STATUS "  mount.cifs:  ${MOUNT_CIFS_EXECUTABLE}")
message(STATUS "")
