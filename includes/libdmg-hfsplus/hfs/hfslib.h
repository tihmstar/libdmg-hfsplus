#include <libdmg-hfsplus/hfs/hfsplus.h>
#include <libdmg-hfsplus/common.h>
#include <libdmg-hfsplus/abstractfile.h>

#ifdef __cplusplus
extern "C" {
#endif
	void writeToFile(HFSPlusCatalogFile* file, AbstractFile* output, Volume* volume);
	void writeToHFSFile(HFSPlusCatalogFile* file, AbstractFile* input, Volume* volume);
	void get_hfs(Volume* volume, const char* inFileName, AbstractFile* output);
	int add_hfs(Volume* volume, AbstractFile* inFile, const char* outFileName);
	void grow_hfs(Volume* volume, uint64_t newSize);
	void removeAllInFolder(HFSCatalogNodeID folderID, Volume* volume, const char* parentName);
	void addAllInFolder(HFSCatalogNodeID folderID, Volume* volume, const char* parentName);
	void addall_hfs(Volume* volume, const char* dirToMerge, const char* dest);
	void extractAllInFolder(HFSCatalogNodeID folderID, Volume* volume);
	int copyAcrossVolumes(Volume* volume1, Volume* volume2, char* path1, char* path2);

	/* Extracts regular files, directories and symlinks from V7/USTAR/GNU tar.
	 * Validates the entire archive first; unsupported entry types fail validation.
	 * Paths are limited to 4095 bytes, components to 255, link targets to 1023.
	 * Returns FALSE on failure. Does not close tarFile or roll back prior writes. */
	int hfs_untar_checked(Volume* volume, AbstractFile* tarFile);
	void hfs_untar(Volume* volume, AbstractFile* tarFile);
	void hfs_ls(Volume* volume, const char* path);
	void hfs_setsilence(int s);
#ifdef __cplusplus
}
#endif
