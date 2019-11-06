#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <assert.h>
#include "streamer.h"

#define JC_TEST_IMPLEMENTATION
#include "jc_test.h"

template <class T>
class offset_ptr {
private:
	ptrdiff_t diff;

public:
	offset_ptr() : diff(0) {}
	offset_ptr(const T* ptr) : diff((ptrdiff_t)ptr - (ptrdiff_t)this) {}
	offset_ptr(const offset_ptr &v) : diff((ptrdiff_t)v.get() - (ptrdiff_t)this) {}
	~offset_ptr() {}

	T* get() { return (T*)((ptrdiff_t)this + diff); }
	const T* get() const { return (T*)((ptrdiff_t)this + diff); }

	T& operator*() { return *get(); }
	const T& operator*() const { return *get(); }

	T* operator->() { return get(); }
	const T* operator->() const { return get(); }

	offset_ptr<T>& operator=(const offset_ptr &other) {
		diff = (ptrdiff_t)other.get() - (ptrdiff_t)this;
		return *this
	}

	offset_ptr<T>& operator=(const T* ptr) {
		diff = (ptrdiff_t)ptr - (ptrdiff_t)this;
		return *this;
	}
};

#pragma warning(disable : 4200)
struct resource_t
{
	offset_ptr<resource_t> next;
	uint8_t data[];
};

#define NUM_RESOURCES 256

TEST(streamer, create_destroy) {
	streamer_create_info_t create_info = {};
	create_info.flags = STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE;
	create_info.path = "d:\\streamer";
	create_info.address_space_size = 0x0000010000000000ULL;
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
	create_info.flags = STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE;
	create_info.path = "d:\\streamer";
	create_info.address_space_size = 0x0000010000000000ULL;
	create_info.page_padding_multiplier = 10;
	streamer_result_t res = streamer_create(&create_info, &streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	size_t size = 1024 * 1024;
	streamer_resource_id_t resource_ids[NUM_RESOURCES];
	resource_t* ptrs[NUM_RESOURCES];
	for (int i = 0; i < NUM_RESOURCES; ++i)
	{
		res = streamer_allocate_resource(streamer, size, &resource_ids[i], (void**)&ptrs[i]);
		ASSERT_EQ(res, STREAMER_RESULT_OK);
	}

	for (int i = 0; i < NUM_RESOURCES; ++i)
	{
		ptrs[i]->next = ptrs[(i + 1) % NUM_RESOURCES];
		memset(ptrs[i]->data, i, size - sizeof(resource_t));
	}

	size *= 4;
	for (int i = 0; i < 256; ++i)
	{
		res = streamer_grow_resource(streamer, size, resource_ids[i]);
		ASSERT_EQ(res, STREAMER_RESULT_OK);

		ASSERT_EQ(ptrs[i]->next->data[0], (i + 1) % NUM_RESOURCES);
		ASSERT_EQ(ptrs[i]->data[0], i);

		memset(ptrs[i]->data, i, size - sizeof(resource_t));
	}

	res = streamer_flush_all_to_disk(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	res = streamer_destroy(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	create_info.flags = 0;
	res = streamer_create(&create_info, &streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);

	for (int i = 0; i < NUM_RESOURCES; ++i)
	{
		void* ptr = nullptr;
		res = streamer_load_resource(streamer, resource_ids[i], &ptr);
		ASSERT_EQ(res, STREAMER_RESULT_OK);

		ASSERT_EQ(ptrs[i]->next->data[0], (i + 1) % NUM_RESOURCES);
		ASSERT_EQ(ptrs[i]->data[0], i);
	}

	res = streamer_destroy(streamer);
	ASSERT_EQ(res, STREAMER_RESULT_OK);
}

int main(int argc, char *argv[])
{
	jc_test_init(&argc, argv);
	int res = jc_test_run_all();
	return res;
}
