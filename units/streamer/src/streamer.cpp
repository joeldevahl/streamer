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
	streamer_resource_id_t id;
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

struct streamer_path_t
{
	char* path;
};

struct streamer_space_t
{
	size_t address_space_size;

	int num_paths;
	streamer_path_t* paths;

	uint8_t* base_ptr;

	streamer_page_map_t* page_map;
	streamer_resource_status_t* resource_statuses;
	size_t* resource_to_path;

	HANDLE page_map_file;
	HANDLE page_map_file_mapping;
};

struct streamer_t
{
	uint32_t creation_flags;
	size_t allocation_padding_multiplier;

	int num_spaces;
	streamer_space_t* spaces;
};

streamer_result_t streamer_create(const streamer_create_info_t* create_info, streamer_t** out_streamer)
{
	if(create_info->num_spaces < 1)
		return STREAMER_RESULT_GENERIC_ERROR;

	streamer_t* streamer = (streamer_t*)malloc(sizeof(streamer_t));

	streamer->creation_flags = create_info->flags;
	streamer->allocation_padding_multiplier = create_info->allocation_padding_multiplier;

	// Get system info since we need to know about allocation granularity
	// We use this granularity as a allocation "page"
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	size_t page_size = sysinfo.dwAllocationGranularity;

	streamer->num_spaces = create_info->num_spaces;
	streamer->spaces = (streamer_space_t*)malloc(streamer->num_spaces * sizeof(streamer_space_t));
	for (size_t is = 0; is < streamer->num_spaces; ++is)
	{
		streamer_space_t* space = &streamer->spaces[is];
		const streamer_space_info_t* space_info = &create_info->spaces[is];

		if (space_info->num_paths < 1)
			return STREAMER_RESULT_GENERIC_ERROR; // TODO: rollback and free what was already allocated;
		
		space->address_space_size = space_info->address_space_size;

		space->num_paths = space_info->num_paths;
		space->paths = (streamer_path_t*)malloc(space->num_paths * sizeof(streamer_path_t));
		for (size_t ip = 0; ip < space->num_paths; ++ip)
		{
			streamer_path_t* path = &space->paths[ip];
			const streamer_path_info_t* path_info = &space_info->paths[ip];

			path->path = _strdup(path_info->path);

			// TODO: we should be able to nuke just _some_ directories
			if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
			{
				std::experimental::filesystem::remove_all(path->path);
				CreateDirectory(path->path, NULL);
			}
		}

		space->base_ptr = (uint8_t*)VirtualAlloc(NULL, space->address_space_size, MEM_RESERVE, PAGE_READWRITE);
		if (space->base_ptr == NULL)
			return STREAMER_RESULT_GENERIC_ERROR; // TODO: rollback and free what was already allocated;

		// Setup page map
		char name[MAX_PATH];
		sprintf(name, "%s\\page_map.dat", space->paths[0].path);
		space->page_map_file = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		size_t size = 0;
		size_t num_pages = 0;

		if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
		{
			// We are resetting so set up an initial space of resources
			// This can be grown later on
			size = sizeof(streamer_page_map_t) + 1024 * sizeof(streamer_resource_info_t);
			num_pages = (size + page_size - 1) / page_size;
			size = num_pages * page_size;
			if (streamer->allocation_padding_multiplier > 0)
				num_pages *= streamer->allocation_padding_multiplier;
		}
		else
		{
			// We are not resetting so we just get the size to map from the file
			DWORD size_high = 0;
			DWORD size_low = GetFileSize(space->page_map_file, &size_high);
			size = (size_t)size_low + (((size_t)size_high) << 32);
			num_pages = (size + page_size - 1) / page_size;
		}

		DWORD size_low = (DWORD)size;
		DWORD size_high = (DWORD)(size >> 32);
		space->page_map_file_mapping = CreateFileMapping(space->page_map_file, NULL, PAGE_READWRITE, size_high, size_low, NULL);
		void* mem = MapViewOfFileEx(space->page_map_file_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size, NULL);

		space->page_map = (streamer_page_map_t*)mem;
		if (create_info->flags & STREAMER_CREATE_FLAGS_CLEAN_ON_CREATE)
		{
			space->page_map->page_size = page_size;
			space->page_map->allocation_offset = 0;
			space->page_map->info_count = 0;
			space->page_map->info_capacity = 1024;
		}
		assert(space->page_map->page_size == page_size);

		// Allocate some supporting structures
		space->resource_statuses = (streamer_resource_status_t*)malloc(space->page_map->info_capacity * sizeof(streamer_resource_status_t));
		memset(space->resource_statuses, 0, space->page_map->info_capacity * sizeof(streamer_resource_status_t));
		space->resource_to_path = (size_t*)malloc(space->page_map->info_capacity * sizeof(size_t));
	}

	*out_streamer = streamer;
	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_destroy(streamer_t* streamer)
{
	for (size_t is = 0; is < streamer->num_spaces; ++is)
	{
		streamer_space_t* space = &streamer->spaces[is];
		for (size_t ip = 0; ip < space->num_paths; ++ip)
		{
			streamer_path_t* path = &space->paths[ip];
			free(path->path);
		}
		free(space->paths);
		free(space->resource_statuses);
		free(space->resource_to_path);
		UnmapViewOfFile(space->page_map);
		CloseHandle(space->page_map_file_mapping);
		CloseHandle(space->page_map_file);
		VirtualFree(space->base_ptr, space->address_space_size, MEM_RELEASE);
	}
	free(streamer->spaces);
	free(streamer);

	return STREAMER_RESULT_OK;
}

static int streamer_compare_func(const void * a, const void * b) {
	streamer_resource_info_t* info_a = (streamer_resource_info_t*)a;
	streamer_resource_info_t* info_b = (streamer_resource_info_t*)b;
	return (int)(info_a->id.id - info_b->id.id);
}

static streamer_resource_info_t* streamer_find_resource_info(streamer_space_t* space, streamer_resource_id_t resource_id)
{
	streamer_resource_info_t info = {};
	info.id = resource_id;
	return (streamer_resource_info_t*)bsearch(&info, space->page_map->infos, space->page_map->info_count, sizeof(streamer_resource_info_t), streamer_compare_func);
}

static size_t streamer_resource_info_to_index(streamer_space_t* space, streamer_resource_info_t* info)
{
	return (info - space->page_map->infos);
}

streamer_result_t streamer_get_resource_status(streamer_t* streamer, streamer_resource_id_t resource_id, streamer_resource_status_t* out_status)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(space, info);
	*out_status = space->resource_statuses[index];
	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_load_resource(streamer_t* streamer, streamer_resource_id_t resource_id, void** out_ptr)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(space, info);
	if(space->resource_statuses[index] != STREAMER_RESOURCE_STATUS_NON_RESIDENT)
		return STREAMER_RESULT_OK;

	streamer_result_t res = STREAMER_RESULT_GENERIC_ERROR;
	for (int i = space->num_paths - 1; i >= 0 && res != STREAMER_RESULT_OK; --i)
	{
		char name[MAX_PATH];
		sprintf(name, "%s\\0x%016" PRIx64 ".dat", space->paths[i].path, resource_id.id);

		HANDLE file = CreateFile(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file != INVALID_HANDLE_VALUE)
		{
			HANDLE file_mapping = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, 0, NULL);
			if (file_mapping != NULL)
			{
				void* src = MapViewOfFileEx(file_mapping, FILE_MAP_READ, 0, 0, info->size, NULL);
				if (src != NULL)
				{
					void* dst = VirtualAlloc(space->base_ptr + resource_id.id, info->size, MEM_COMMIT, PAGE_READWRITE);
					if (dst != NULL)
					{
						memcpy(dst, src, info->size);
						*out_ptr = dst;
						space->resource_statuses[index] = STREAMER_RESOURCE_STATUS_NON_RESIDENT;
						space->resource_to_path[index] = i;
						res = STREAMER_RESULT_OK;
					}
					UnmapViewOfFile(src);
				}
				CloseHandle(file_mapping);
			}
			CloseHandle(file);
		}
	}

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_free_resource(streamer_t* streamer, streamer_resource_id_t resource_id)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(space, info);
	if(space->resource_statuses[index] != STREAMER_RESOURCE_STATUS_NON_RESIDENT)
	{
		VirtualFree(space->base_ptr + resource_id.id, info->size, MEM_DECOMMIT);
		space->resource_statuses[index] = STREAMER_RESOURCE_STATUS_NON_RESIDENT;
	}

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_allocate_resource(streamer_t* streamer, uint8_t space_index, size_t size, streamer_resource_id_t* out_resource_id, void** out_ptr)
{
	streamer_space_t* space = &streamer->spaces[space_index];
	streamer_resource_id_t resource_id = { space->page_map->allocation_offset };

	// round up to the nearest number of pages
	size_t num_pages = (size + space->page_map->page_size - 1) / space->page_map->page_size;

	// and pad the size to be page aligned
	size = num_pages * space->page_map->page_size;

	// if we want extra padding in the virtual address space (not allocated or stored) we handle that here
	if (streamer->allocation_padding_multiplier > 0)
		num_pages *= streamer->allocation_padding_multiplier;

	size_t capacity = num_pages * space->page_map->page_size;
	space->page_map->allocation_offset += capacity;

	void* mem = VirtualAlloc(space->base_ptr + resource_id.id, size, MEM_COMMIT, PAGE_READWRITE);
	if(mem == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	assert(space->page_map->info_count < space->page_map->info_capacity); // TODO: grow/realloc
	size_t index = space->page_map->info_count;
	space->page_map->info_count += 1;

	streamer_resource_info_t* info = &space->page_map->infos[index];
	info->id = resource_id;
	info->size = size;
	info->capacity = capacity;

	space->resource_statuses[index] = STREAMER_RESOURCE_STATUS_RESIDENT;

	*out_resource_id = resource_id;
	*out_ptr = mem;

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_delete_resource(streamer_t* streamer, size_t size, streamer_resource_id_t resource_id)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if (info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	size_t index = streamer_resource_info_to_index(space, info);
	size_t path_index = space->resource_to_path[index];

	VirtualFree(space->base_ptr + resource_id.id, info->size, MEM_DECOMMIT);

	size_t num_to_move = space->page_map->info_count - index - 1;
	memmove(&space->page_map->infos[index], &space->page_map->infos[index + 1], sizeof(streamer_resource_info_t) * num_to_move);
	memmove(&space->resource_statuses[index], &space->resource_statuses[index + 1], sizeof(streamer_resource_status_t) * num_to_move);
	memmove(&space->resource_to_path[index], &space->resource_to_path[index + 1], sizeof(size_t) * num_to_move);

	space->page_map->info_count -= 1;

	char name[MAX_PATH];
	sprintf(name, "%s\\0x%016" PRIx64 ".dat", space->paths[path_index].path, resource_id.id);
	std::experimental::filesystem::remove(name);

	return STREAMER_RESULT_OK;
}

streamer_result_t streamer_grow_resource(streamer_t* streamer, size_t new_size, streamer_resource_id_t resource_id)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	if(info->capacity <= new_size)
		return STREAMER_RESULT_GENERIC_ERROR;

	if(info->size >= new_size)
		return STREAMER_RESULT_OK;

	size_t num_pages = (new_size + space->page_map->page_size - 1) / space->page_map->page_size;
	new_size = num_pages * space->page_map->page_size;

	void* mem = VirtualAlloc(space->base_ptr + resource_id.id, new_size, MEM_COMMIT, PAGE_READWRITE);
	assert(mem == space->base_ptr + resource_id.id);

	info->size = new_size;

	return STREAMER_RESULT_OK;
}

static streamer_result_t streamer_flush_to_disk_internal(streamer_space_t* space, streamer_resource_info_t* info)
{
	streamer_result_t res = STREAMER_RESULT_OK;

	size_t index = streamer_resource_info_to_index(space, info);
	size_t path_index = space->resource_to_path[index];

	char name[MAX_PATH];
	sprintf(name, "%s\\0x%016" PRIx64 ".dat", space->paths[path_index].path, info->id.id);

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
				memcpy(dst, space->base_ptr + info->id.id, info->size);
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

streamer_result_t streamer_flush_to_disk(streamer_t* streamer, streamer_resource_id_t resource_id)
{
	streamer_space_t* space = &streamer->spaces[resource_id.space];
	streamer_resource_info_t* info = streamer_find_resource_info(space, resource_id);
	if(info == NULL)
		return STREAMER_RESULT_GENERIC_ERROR;

	return streamer_flush_to_disk_internal(space, info);
}

streamer_result_t streamer_flush_all_to_disk(streamer_t* streamer)
{
	for (size_t is = 0; is < streamer->num_spaces; ++is)
	{
		streamer_space_t* space = &streamer->spaces[is]; // TODO: only one space?
		for (size_t i = 0; i < space->page_map->info_count; ++i)
		{
			streamer_resource_info_t* info = &space->page_map->infos[i];
			streamer_flush_to_disk_internal(space, info); // TODO: what if one errors?
		}
	}

	return STREAMER_RESULT_OK;
}
