#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <streamer.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <filesystem> // To be able to delete directories...

struct streamer_resource_info_t
{
	streamer_resource_t* resource;
	void* addr;
	size_t size;
	size_t capacity;
};

#pragma warning(disable : 4200)
struct streamer_page_map_t
{
	size_t page_size;
	size_t allocation_offset;
	size_t info_count;
	size_t info_capacity;
	streamer_resource_info_t infos[];
};

struct streamer_t
{
	char* base_path;
	uint32_t creation_flags;
	size_t page_padding_multiplier;

	size_t base_address;
	size_t base_size;
	void* base_ptr;

	streamer_page_map_t* page_map;
	streamer_resource_status_t* resource_statuses;

	HANDLE page_map_file;
	HANDLE page_map_file_mapping;
};

streamer_result_t streamer_create(const streamer_create_info_t* create_info, streamer_t** out_streamer)
{
	streamer_t* streamer = (streamer_t*)malloc(sizeof(streamer_t));
	streamer->base_path = _strdup(create_info->base_path);
	streamer->creation_flags = create_info->flags;
	streamer->page_padding_multiplier = create_info->page_padding_multiplier;

	streamer->base_address = create_info->base_address;
	streamer->base_size = create_info->base_size;

	// If we are to use a managed virtual address space, allocate it up front
	if (create_info->flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		streamer->base_ptr = VirtualAlloc((void*)streamer->base_address, streamer->base_size, MEM_RESERVE, PAGE_READWRITE);
	else
		streamer->base_ptr = NULL;
	
	// Get system info since we need to know about allocation granularity
	// We use this granularity as a allocation "page"
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	size_t page_size = sysinfo.dwAllocationGranularity;

	if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
	{
		//RemoveDirectory(streamer->base_path); // does nothing, need to delete all files in it first :/
		std::experimental::filesystem::remove_all(streamer->base_path);
		CreateDirectory(streamer->base_path, NULL);
	}

	// Setup page map
	{
		char name[MAX_PATH];
		sprintf(name, "%s\\page_map.dat", streamer->base_path);
		streamer->page_map_file = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		size_t size = 0;
		size_t num_pages = 0;

		if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
		{
			// We are resetting so set up an initial space of resources
			// This can be grown later on
			size = sizeof(streamer_page_map_t) + 1024 * sizeof(streamer_resource_info_t);
			num_pages = (size + page_size - 1) / page_size;
			size = num_pages * page_size;
			if (create_info->page_padding_multiplier > 0)
				num_pages *= create_info->page_padding_multiplier;
		}
		else
		{
			// We are not resetting so we just get the size to map from the file
			DWORD size_high = 0;
			DWORD size_low = GetFileSize(streamer->page_map_file, &size_high);
			size = (size_t)size_low + (((size_t)size_high) << 32);
			num_pages = (size + page_size - 1) / page_size;
		}

		DWORD size_low = (DWORD)size;
		DWORD size_high = (DWORD)(size >> 32);
		streamer->page_map_file_mapping = CreateFileMapping(streamer->page_map_file, NULL, PAGE_READWRITE, size_high, size_low, NULL);
		void* mem = MapViewOfFileEx(streamer->page_map_file_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, NULL);

		streamer->page_map = (streamer_page_map_t*)mem;
		if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
		{
				streamer->page_map->page_size = page_size;
				streamer->page_map->allocation_offset = 0;
				streamer->page_map->info_count = 0;
				streamer->page_map->info_capacity = 1024;
		}
		assert(streamer->page_map->page_size == page_size);

		// Allocate some supporting structures
		streamer->resource_statuses = (streamer_resource_status_t*)malloc(streamer->page_map->info_capacity * sizeof(streamer_resource_status_t));
		memset(streamer->resource_statuses, 0, streamer->page_map->info_capacity * sizeof(streamer_resource_status_t));
	}

	*out_streamer = streamer;
	return STREAMER_RESULT_OK;
}

static void streamer_release_internal(streamer_t* streamer)
{
	UnmapViewOfFile(streamer->page_map);
	CloseHandle(streamer->page_map_file_mapping);
	CloseHandle(streamer->page_map_file);

	if (streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		VirtualFree(streamer->base_ptr, streamer->base_size, MEM_RELEASE);
}

static void streamer_free_internal(streamer_t* streamer)
{
	free(streamer->resource_statuses);
	free(streamer->base_path);
	free(streamer);
}

streamer_result_t streamer_destroy(streamer_t* streamer)
{
	streamer_release_internal(streamer);
	streamer_free_internal(streamer);

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_destroy_and_clear(streamer_t* streamer)
{
	streamer_release_internal(streamer);

	std::experimental::filesystem::remove_all(streamer->base_path);

	streamer_free_internal(streamer);
	return STREAMER_RESULT_OK;
}

static int streamer_compare_func(const void * a, const void * b) {
	streamer_resource_info_t* info_a = (streamer_resource_info_t*)a;
	streamer_resource_info_t* info_b = (streamer_resource_info_t*)b;
	return (int)((ptrdiff_t)info_a->resource - (ptrdiff_t)info_b->resource);
}

static streamer_resource_info_t* streamer_find_resource_info(streamer_t* streamer, streamer_resource_t* resource)
{
	streamer_resource_info_t info = {};
	info.resource = resource;
	return (streamer_resource_info_t*)bsearch(&info, streamer->page_map->infos, streamer->page_map->info_count, sizeof(streamer_resource_info_t), streamer_compare_func);
}

static size_t streamer_resource_info_to_index(streamer_t* streamer, streamer_resource_info_t* info)
{
	return (info - streamer->page_map->infos);
}

streamer_result_t streamer_get_resource_status(streamer_t* streamer, streamer_resource_t* resource, streamer_resource_status_t* out_status)
{
	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(streamer, info);
	*out_status = streamer->resource_statuses[index];
	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_load_resource(streamer_t* streamer, streamer_resource_t* resource, void** out_ptr)
{
	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(streamer, info);
	if(streamer->resource_statuses[index] != STREAMER_RESOURCE_STATUS_NON_RESIDENT)
		return STREAMER_RESULT_OK;

	char name[MAX_PATH];
	sprintf(name, "%s\\0x%016" PRIx64 ".dat", streamer->base_path, (uint64_t)resource);

	HANDLE file = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file == INVALID_HANDLE_VALUE)
		return STREAMER_RESULT_GENERIC_ERROR;

	HANDLE file_mapping = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (file_mapping == NULL)
	{
		CloseHandle(file);
		return STREAMER_RESULT_GENERIC_ERROR;
	}

	void* src = MapViewOfFileEx(file_mapping, FILE_MAP_READ, 0, 0, info->size, NULL);
	if (src == NULL)
	{
		CloseHandle(file_mapping);
		CloseHandle(file);
		return STREAMER_RESULT_GENERIC_ERROR;
	}

	void* dst = NULL;
	if(streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		dst = VirtualAlloc(resource, info->size, MEM_COMMIT, PAGE_READWRITE);
	else
		dst = VirtualAlloc(NULL, info->size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (dst == NULL)
	{
		UnmapViewOfFile(src);
		CloseHandle(file_mapping);
		CloseHandle(file);
		return STREAMER_RESULT_GENERIC_ERROR;
	}

	memcpy(dst, src, info->size);

	*out_ptr = dst;

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_free_resource(streamer_t* streamer, streamer_resource_t* resource)
{
	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(streamer, info);
	if(streamer->resource_statuses[index] != STREAMER_RESOURCE_STATUS_NON_RESIDENT)
	{
		if (streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
			VirtualFree(resource, info->size, MEM_DECOMMIT);
		else
			VirtualFree(resource, info->size, MEM_RELEASE | MEM_DECOMMIT);
		streamer->resource_statuses[index] = STREAMER_RESOURCE_STATUS_NON_RESIDENT;
	}

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_allocate_resource(streamer_t* streamer, size_t size, streamer_resource_t** out_resource, void** out_ptr)
{
	if(!(streamer->creation_flags & STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION))
		return STREAMER_RESULT_GENERIC_ERROR;

	// TODO: better name generation here if we have no fixed base address?
	// TODO: perhaps we could have a pluggable name generator
	streamer_resource_t* resource = (streamer_resource_t*)(streamer->base_address + streamer->page_map->allocation_offset);

	// round up to the nearest number of pages
	size_t num_pages = (size + streamer->page_map->page_size - 1) / streamer->page_map->page_size;

	// and pad the size to be page aligned
	size = num_pages * streamer->page_map->page_size;

	// if we want extra padding in the virtual address space (not allocated or stored) we handle that here
	if (streamer->page_padding_multiplier > 0)
		num_pages *= streamer->page_padding_multiplier;

	size_t capacity = num_pages * streamer->page_map->page_size;
	streamer->page_map->allocation_offset += capacity;

	void* mem = NULL;
	if(streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		mem = VirtualAlloc(resource, size, MEM_COMMIT, PAGE_READWRITE);
	else
		mem = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	assert(streamer->page_map->info_count < streamer->page_map->info_capacity); // TODO: grow/realloc
	size_t index = streamer->page_map->info_count;
	streamer->page_map->info_count += 1;

	streamer_resource_info_t* info = &streamer->page_map->infos[index];
	info->resource = resource;
	info->addr = mem;
	info->size = size;
	info->capacity = capacity;

	streamer->resource_statuses[index] = STREAMER_RESOURCE_STATUS_RESIDENT;

	*out_resource = resource;
	*out_ptr = mem;

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_delete_resource(streamer_t* streamer, size_t size, streamer_resource_t* resource)
{
	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(streamer, info);

	if (streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		VirtualFree(resource, info->size, MEM_DECOMMIT);
	else
		VirtualFree(resource, info->size, MEM_RELEASE | MEM_DECOMMIT);

	size_t num_to_move = streamer->page_map->info_count - index - 1;
	memmove(&streamer->page_map->infos[index], &streamer->page_map->infos[index + 1], sizeof(streamer_resource_info_t) * num_to_move);
	memmove(&streamer->resource_statuses[index], &streamer->resource_statuses[index + 1], sizeof(streamer_resource_status_t) * num_to_move);

	streamer->page_map->info_count -= 1;

	char name[MAX_PATH];
	sprintf(name, "%s\\0x%016" PRIx64 ".dat", streamer->base_path, (uint64_t)resource);
	std::experimental::filesystem::remove(name);

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_grow_resource(streamer_t* streamer, size_t new_size, streamer_resource_t* resource)
{
	if(!(streamer->creation_flags & STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION))
		return STREAMER_RESULT_GENERIC_ERROR;

	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	if(info->capacity <= new_size)
		return STREAMER_RESULT_GENERIC_ERROR;

	if(info->size >= new_size)
		return STREAMER_RESULT_OK;

	size_t num_pages = (new_size + streamer->page_map->page_size - 1) / streamer->page_map->page_size;
	new_size = num_pages * streamer->page_map->page_size;

	void* mem = NULL;
	if(streamer->creation_flags & STREAMER_CREATE_FLAGS_FIXED_BASE_ADDRESS)
		mem = VirtualAlloc(resource, new_size, MEM_COMMIT, PAGE_READWRITE);
	else
		mem = VirtualAlloc(info->addr, new_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	assert(mem == info->addr);

	info->size = new_size;

	return STREAMER_RESULT_OK;
}

static streamer_result_t streamer_flush_to_disk_internal(streamer_t* streamer, streamer_resource_t* resource, streamer_resource_info_t* info)
{
	streamer_result_t res = STREAMER_RESULT_OK;

	char name[MAX_PATH];
	sprintf(name, "%s\\0x%016" PRIx64 ".dat", streamer->base_path, (uint64_t)resource);

	HANDLE file = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file != INVALID_HANDLE_VALUE)
	{
		DWORD size_low = (DWORD)info->size;
		DWORD size_high = (DWORD)(info->size >> 32);
		HANDLE file_mapping = CreateFileMapping(file, NULL, PAGE_READWRITE, size_high, size_low, NULL);
		if (file_mapping != NULL)
		{
			void* dst = MapViewOfFileEx(file_mapping, FILE_MAP_WRITE, 0, 0, info->size, NULL);
			if (dst != NULL)
			{
				memcpy(dst, info->addr, info->size);
				UnmapViewOfFile(dst);
			}
			else
				res = STREAMER_RESULT_GENERIC_ERROR;
			CloseHandle(file_mapping);
		}
		else
			res = STREAMER_RESULT_GENERIC_ERROR;
		CloseHandle(file);
	}
	else
		res = STREAMER_RESULT_GENERIC_ERROR;

	return res;
}

streamer_result_t streamer_flush_to_disk(streamer_t* streamer, streamer_resource_t* resource)
{
	if(!(streamer->creation_flags & STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION))
		return STREAMER_RESULT_GENERIC_ERROR;

	streamer_resource_info_t* info = streamer_find_resource_info(streamer, resource);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	return streamer_flush_to_disk_internal(streamer, resource, info);
}

streamer_result_t streamer_flush_all_to_disk(streamer_t* streamer)
{
	if(!(streamer->creation_flags & STREAMER_CREATE_FLAGS_ALLOW_ALLOCATION))
		return STREAMER_RESULT_GENERIC_ERROR;

	for (size_t i = 0; i < streamer->page_map->info_count; ++i)
	{
		streamer_resource_info_t* info = &streamer->page_map->infos[i];
		streamer_flush_to_disk_internal(streamer, info->resource, info); // TODO: what if one errors?
	}

	return STREAMER_RESULT_OK;
}
