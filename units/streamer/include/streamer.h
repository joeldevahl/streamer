#pragma once

#include <stddef.h> // for size_t
#include <stdint.h> // for uint64_t

struct streamer_t;

struct streamer_resource_id_t
{
	uint64_t id;
};

enum streamer_result_t
{
	STREAMER_RESULT_OK = 0,
	STREAMER_RESULT_GENERIC_ERROR,
};

enum streamer_resource_status_t
{
	STREAMER_RESOURCE_STATUS_NON_RESIDENT = 0,
	STREAMER_RESOURCE_STATUS_RESIDENT,
};

enum streamer_create_flags_t
{
	STREAMER_CREATE_FLAGS_NONE               = 0,
	STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION   = 1,
	STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE    = 2 | STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION,
};

struct streamer_create_info_t
{
	uint32_t flags;

	const char* path;
	size_t address_space_size;

	size_t page_padding_multiplier;
};

streamer_result_t streamer_create(const streamer_create_info_t* create_info, streamer_t** out_streamer);
streamer_result_t streamer_destroy(streamer_t* streamer);
streamer_result_t streamer_destroy_and_clear(streamer_t* streamer);

streamer_result_t streamer_get_resource_status(streamer_t* streamer, streamer_resource_id_t resource_id, streamer_resource_status_t* out_status);
streamer_result_t streamer_load_resource(streamer_t* streamer, streamer_resource_id_t resource_id, void** out_ptr);
streamer_result_t streamer_free_resource(streamer_t* streamer, streamer_resource_id_t resource_id);

// only supported if STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION is set
streamer_result_t streamer_allocate_resource(streamer_t* streamer, size_t size, streamer_resource_id_t* out_resourc_ide, void** out_ptr);
streamer_result_t streamer_delete_resource(streamer_t* streamer, size_t size, streamer_resource_id_t resource_id);
streamer_result_t streamer_grow_resource(streamer_t* streamer, size_t new_size, streamer_resource_id_t resource_id);
streamer_result_t streamer_flush_to_disk(streamer_t* streamer, streamer_resource_id_t resource_id);
streamer_result_t streamer_flush_all_to_disk(streamer_t* streamer);
