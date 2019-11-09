#pragma once

#include <stddef.h> // for size_t
#include <stdint.h> // for uint64_t

struct streamer_t;

struct streamer_resource_id_t
{
	uint64_t space : 8;
	uint64_t id : 56;
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
	STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE    = 1,
};

struct streamer_path_info_t
{
	const char* path;
};

struct streamer_space_info_t
{
	size_t address_space_size;
	int num_paths;
	streamer_path_info_t* paths;
};

struct streamer_create_info_t
{
	int num_spaces;
	streamer_space_info_t* spaces;
	uint32_t flags; // TODO: flags per space and path

	size_t allocation_padding_multiplier; // TODO: not global?
};

streamer_result_t streamer_create(const streamer_create_info_t* create_info, streamer_t** out_streamer);
streamer_result_t streamer_destroy(streamer_t* streamer);

streamer_result_t streamer_get_resource_status(streamer_t* streamer, streamer_resource_id_t resource_id, streamer_resource_status_t* out_status);
streamer_result_t streamer_load_resource(streamer_t* streamer, streamer_resource_id_t resource_id, void** out_ptr);
streamer_result_t streamer_free_resource(streamer_t* streamer, streamer_resource_id_t resource_id);

streamer_result_t streamer_allocate_resource(streamer_t* streamer, uint8_t space_index, size_t size, streamer_resource_id_t* out_resource_id, void** out_ptr);
streamer_result_t streamer_delete_resource(streamer_t* streamer, size_t size, streamer_resource_id_t resource_id);
streamer_result_t streamer_grow_resource(streamer_t* streamer, size_t new_size, streamer_resource_id_t resource_id);
streamer_result_t streamer_flush_to_disk(streamer_t* streamer, streamer_resource_id_t resource_id);
streamer_result_t streamer_flush_all_to_disk(streamer_t* streamer);
