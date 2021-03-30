#
# Copyright (C) 2013-2021 Draios Inc dba Sysdig.
#
# This file is part of sysdig.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_directories("${JSONCPP_INCLUDE}")

if(NOT WIN32)
	include_directories("${TBB_INCLUDE_DIR}")
	if(NOT MINIMAL_BUILD)
		include_directories("${CURL_INCLUDE_DIR}")
	endif() # MINIMAL_BUILD
	include_directories("${CURSES_INCLUDE_DIR}")
endif() # NOT WIN32

include_directories("${PROJECT_SOURCE_DIR}/common")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libscap")
include_directories("${PROJECT_SOURCE_DIR}/userspace/libsinsp")
include_directories("${PROJECT_BINARY_DIR}/userspace/indexer")
include_directories(.)

if(NOT WIN32)
	set(SOURCE_FILES
		sdindexer.cpp)
else()
	set(SOURCE_FILES
		sdindexer.cpp
		win32/getopt.c)
endif()

add_executable(sdindexer ${SOURCE_FILES})

if(NOT WIN32)
	include_directories(${PROJECT_BINARY_DIR}/driver/src)
	target_link_libraries(sdindexer
		sinsp)

	install(TARGETS sdindexer 
		DESTINATION bin)
else()
	target_link_libraries(sdindexer
		sinsp)

	target_link_libraries(sdindexer odbc32.lib odbccp32.lib Netapi32.lib Iphlpapi.lib)

	add_custom_command(TARGET sdindexer POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${LUAJIT_SRC}/lua51.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/lua51.dll")

	add_custom_command(TARGET sdindexer POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			"${ZLIB_INCLUDE}/zlib1.dll"
			"${PROJECT_BINARY_DIR}/$(Configuration)/")

	add_custom_command(TARGET sdindexer POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E copy_if_different
			$<TARGET_FILE:sdindexer>
			"${PROJECT_BINARY_DIR}/$(Configuration)/sdindexer.exe")
endif()
