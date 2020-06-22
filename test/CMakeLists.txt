
add_executable(test_ztls
	test.cpp
)

target_link_libraries(test_ztls zerotls)

if (WIN32)
	target_link_libraries(test_ztls ws2_32.lib)
endif()