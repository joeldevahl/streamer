#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <assert.h>
#include "streamer.h"

#define JC_TEST_IMPLEMENTATION
#include "jc_test.h"

#define NUM_RESOURCES 256

TEST(streamer, create_destroy) {
	streamer_create_info_t create_info = {};
	create_info.flags = STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE;
	create_info.base_path = "d:\\streamer";
	create_info.base_address = 0x0000000150000000ULL;
	create_info.base_size = 0x0000010000000000ULL;
	create_info.page_padding_multiplier = 10;

	streamer_t* streamer;
	streamer_result_t res = streamer_create(&create_info, &streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	res = streamer_destroy(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);
}

TEST(streamer, resize_recreate)
{
	streamer_t* streamer;
	streamer_create_info_t create_info = {};
	create_info.flags = STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE | STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS;
	create_info.base_path = "d:\\streamer";
	create_info.base_address = 0x0000000150000000ULL;
	create_info.base_size = 0x0000010000000000ULL;
	create_info.page_padding_multiplier = 10;
	streamer_result_t res = streamer_create(&create_info, &streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	size_t size = 1024 * 1024;
	streamer_resource_t* resources[NUM_RESOURCES];
	void* ptrs[NUM_RESOURCES];
	for (int i = 0; i < NUM_RESOURCES; ++i)
	{
		streamer_resource_t* resource = nullptr;
		res = streamer_allocate_resource(streamer, size, &resource, &ptrs[i]);
		ASSERT_EQ(res, STREAMER_RESULT_OK);

		memset(ptrs[i], i, size);

		resources[i] = resource;
	}

	size *= 4;
	for (int i = 0; i < 256; ++i)
	{
		res = streamer_grow_resource(streamer, size, resources[i]);
		ASSERT_EQ(res, STREAMER_RESULT_OK);

		uint8_t* data = (uint8_t*)ptrs[i];
		ASSERT_EQ(*data, i);

		memset(ptrs[i], i, size);
	}

	res = streamer_flush_all_to_disk(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	res = streamer_destroy(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	create_info.flags = STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS;
	res = streamer_create(&create_info, &streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	for (int i = 0; i < NUM_RESOURCES; ++i)
	{
		void* ptr = nullptr;
		res = streamer_load_resource(streamer, resources[i], &ptr);
		ASSERT_EQ(res, STREAMER_RESULT_OK);
		ASSERT_EQ(ptrs[i], ptr);

		uint8_t* data = (uint8_t*)ptr;
		ASSERT_EQ(*data, i);
	}

	res = streamer_destroy(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);
}

int main(int argc, char *argv[])
{
	jc_test_init(&argc, argv);
	// ... Do your test initialization
	return jc_test_run_all();
}
