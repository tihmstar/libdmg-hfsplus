#include "../includes/libdmg-hfsplus/common.h"
#include "../includes/libdmg-hfsplus/hfs/hfsplus.h"
#include "../includes/libdmg-hfsplus/hfs/hfscompress.h"
#include "../includes/libdmg-hfsplus/abstractfile.h"

#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>

#define BUFSIZE 1024*1024

static int silence = 0;

void hfs_setsilence(int s) {
	silence = s;
}

void writeToFile(HFSPlusCatalogFile* file, AbstractFile* output, Volume* volume) {
	unsigned char* buffer;
	io_func* io;
	off_t curPosition;
	size_t bytesLeft;

	buffer = (unsigned char*) malloc(BUFSIZE);

	if(file->permissions.ownerFlags & UF_COMPRESSED) {
		io = openHFSPlusCompressed(volume, file);
		if(io == NULL) {
			hfs_panic("error opening file");
			free(buffer);
			return;
		}

		curPosition = 0;
		bytesLeft = ((HFSPlusCompressed*) io->data)->decmpfs->size;
	} else {
		io = openRawFile(file->fileID, &file->dataFork, (HFSPlusCatalogRecord*)file, volume);
		if(io == NULL) {
			hfs_panic("error opening file");
			free(buffer);
			return;
		}

		curPosition = 0;
		bytesLeft = file->dataFork.logicalSize;
	}
	while(bytesLeft > 0) {
		if(bytesLeft > BUFSIZE) {
			if(!READ(io, curPosition, BUFSIZE, buffer)) {
				hfs_panic("error reading");
			}
			if(output->write(output, buffer, BUFSIZE) != BUFSIZE) {
				hfs_panic("error writing");
			}
			curPosition += BUFSIZE;
			bytesLeft -= BUFSIZE;
		} else {
			if(!READ(io, curPosition, bytesLeft, buffer)) {
				hfs_panic("error reading");
			}
			if(output->write(output, buffer, bytesLeft) != bytesLeft) {
				hfs_panic("error writing");
			}
			curPosition += bytesLeft;
			bytesLeft -= bytesLeft;
		}
	}
	CLOSE(io);

	free(buffer);
}

void writeToHFSFile(HFSPlusCatalogFile* file, AbstractFile* input, Volume* volume) {
	unsigned char *buffer;
	io_func* io;
	off_t curPosition;
	off_t bytesLeft;

	buffer = (unsigned char*) malloc(BUFSIZE);

	bytesLeft = input->getLength(input);

	if(file->permissions.ownerFlags & UF_COMPRESSED) {
		io = openHFSPlusCompressed(volume, file);
		if(io == NULL) {
			hfs_panic("error opening file");
			free(buffer);
			return;
		}
	} else {
		io = openRawFile(file->fileID, &file->dataFork, (HFSPlusCatalogRecord*)file, volume);
		if(io == NULL) {
			hfs_panic("error opening file");
			free(buffer);
			return;
		}
		allocate((RawFile*)io->data, bytesLeft);
	}

	curPosition = 0;

	while(bytesLeft > 0) {
		if(bytesLeft > BUFSIZE) {
			if(input->read(input, buffer, BUFSIZE) != BUFSIZE) {
				hfs_panic("error reading");
			}
			if(!WRITE(io, curPosition, BUFSIZE, buffer)) {
				hfs_panic("error writing");
			}
			curPosition += BUFSIZE;
			bytesLeft -= BUFSIZE;
		} else {
			if(input->read(input, buffer, (size_t)bytesLeft) != (size_t)bytesLeft) {
				hfs_panic("error reading");
			}
			if(!WRITE(io, curPosition, (size_t)bytesLeft, buffer)) {
				hfs_panic("error reading");
			}
			curPosition += bytesLeft;
			bytesLeft -= bytesLeft;
		}
	}

	CLOSE(io);

	free(buffer);
}

void get_hfs(Volume* volume, const char* inFileName, AbstractFile* output) {
	HFSPlusCatalogRecord* record;

	record = getRecordFromPath(inFileName, volume, NULL, NULL);

	if(record != NULL) {
		if(record->recordType == kHFSPlusFileRecord)
			writeToFile((HFSPlusCatalogFile*)record,  output, volume);
		else {
			printf("Not a file\n");
			exit(0);
		}
	} else {
		printf("No such file or directory\n");
		exit(0);
	}

	free(record);
}

int add_hfs(Volume* volume, AbstractFile* inFile, const char* outFileName) {
	HFSPlusCatalogRecord* record;
	int ret;

	record = getRecordFromPath(outFileName, volume, NULL, NULL);

	if(record != NULL) {
		if(record->recordType == kHFSPlusFileRecord) {
			writeToHFSFile((HFSPlusCatalogFile*)record, inFile, volume);
			ret = TRUE;
		} else {
			printf("Not a file\n");
			exit(0);
		}
	} else {
		if(newFile(outFileName, volume)) {
			record = getRecordFromPath(outFileName, volume, NULL, NULL);
			writeToHFSFile((HFSPlusCatalogFile*)record, inFile, volume);
			ret = TRUE;
		} else {
			ret = FALSE;
		}
	}

	inFile->close(inFile);
	if(record != NULL) {
		free(record);
	}

	return ret;
}

void grow_hfs(Volume* volume, uint64_t newSize) {
	uint32_t newBlocks;
	uint32_t blocksToGrow;
	uint64_t newMapSize;
	uint64_t i;
	unsigned char zero;

	zero = 0;

	newBlocks = newSize / volume->volumeHeader->blockSize;

	if(newBlocks <= volume->volumeHeader->totalBlocks) {
		printf("Cannot shrink volume\n");
		return;
	}

	blocksToGrow = newBlocks - volume->volumeHeader->totalBlocks;
	newMapSize = newBlocks / 8;

	if(volume->volumeHeader->allocationFile.logicalSize < newMapSize) {
		if(volume->volumeHeader->freeBlocks
		   < ((newMapSize - volume->volumeHeader->allocationFile.logicalSize) / volume->volumeHeader->blockSize)) {
			printf("Not enough room to allocate new allocation map blocks\n");
			exit(0);
		}

		allocate((RawFile*) (volume->allocationFile->data), newMapSize);
	}

	/* unreserve last block */
	setBlockUsed(volume, volume->volumeHeader->totalBlocks - 1, 0);
	/* don't need to increment freeBlocks because we will allocate another alternate volume header later on */

	/* "unallocate" the new blocks */
	for(i = ((volume->volumeHeader->totalBlocks / 8) + 1); i < newMapSize; i++) {
		ASSERT(WRITE(volume->allocationFile, i, 1, &zero), "WRITE");
	}

	/* grow backing store size */
	ASSERT(WRITE(volume->image, newSize - 1, 1, &zero), "WRITE");

	/* write new volume information */
	volume->volumeHeader->totalBlocks = newBlocks;
	volume->volumeHeader->freeBlocks += blocksToGrow;

	/* reserve last block */
	setBlockUsed(volume, volume->volumeHeader->totalBlocks - 1, 1);

	updateVolume(volume);
}

void removeAllInFolder(HFSCatalogNodeID folderID, Volume* volume, const char* parentName) {
	CatalogRecordList* list;
	CatalogRecordList* theList;
	char fullName[1024];
	char* name;
	char* pathComponent;
	int pathLen;
	char isRoot;

	HFSPlusCatalogFolder* folder;
	theList = list = getFolderContents(folderID, volume);

	strcpy(fullName, parentName);
	pathComponent = fullName + strlen(fullName);

	isRoot = FALSE;
	if(strcmp(fullName, "/") == 0) {
		isRoot = TRUE;
	}

	while(list != NULL) {
		name = unicodeToAscii(&list->name);
		if(isRoot && (name[0] == '\0' || strncmp(name, ".HFS+ Private Directory Data", sizeof(".HFS+ Private Directory Data") - 1) == 0)) {
			free(name);
			list = list->next;
			continue;
		}

		strcpy(pathComponent, name);
		pathLen = strlen(fullName);

		if(list->record->recordType == kHFSPlusFolderRecord) {
			folder = (HFSPlusCatalogFolder*)list->record;
			fullName[pathLen] = '/';
			fullName[pathLen + 1] = '\0';
			removeAllInFolder(folder->folderID, volume, fullName);
		} else {
			printf("%s\n", fullName);
			removeFile(fullName, volume);
		}

		free(name);
		list = list->next;
	}

	releaseCatalogRecordList(theList);

	if(!isRoot) {
		*(pathComponent - 1) = '\0';
		printf("%s\n", fullName);
		removeFile(fullName, volume);
	}
}


void addAllInFolder(HFSCatalogNodeID folderID, Volume* volume, const char* parentName) {
	CatalogRecordList* list;
	CatalogRecordList* theList;
	char cwd[1024];
	char fullName[1024];
	char testBuffer[1024];
	char* pathComponent;
	int pathLen;

	char* name;

	DIR* dir;
	DIR* tmp;

	HFSCatalogNodeID cnid;

	struct dirent* ent;

	AbstractFile* file;
	HFSPlusCatalogFile* outFile;

	strcpy(fullName, parentName);
	pathComponent = fullName + strlen(fullName);

	ASSERT(getcwd(cwd, 1024) != NULL, "cannot get current working directory");

	theList = list = getFolderContents(folderID, volume);

	ASSERT((dir = opendir(cwd)) != NULL, "opendir");

	while((ent = readdir(dir)) != NULL) {
		if(ent->d_name[0] == '.' && (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
			continue;
		}

		strcpy(pathComponent, ent->d_name);
		pathLen = strlen(fullName);

		cnid = 0;
		list = theList;
		while(list != NULL) {
			name = unicodeToAscii(&list->name);
			if(strcmp(name, ent->d_name) == 0) {
				cnid = (list->record->recordType == kHFSPlusFolderRecord) ? (((HFSPlusCatalogFolder*)list->record)->folderID)
				: (((HFSPlusCatalogFile*)list->record)->fileID);
				free(name);
				break;
			}
			free(name);
			list = list->next;
		}

        struct stat st;
        ASSERT (lstat(ent->d_name, &st) == 0, "lstat");

        if(S_ISLNK(st.st_mode))
        {
            printf("link: %s\n", fullName);	fflush(stdout);

            io_func* io;
            HFSPlusCatalogFile* record;

            record = (HFSPlusCatalogFile*) getRecordFromPath3(fullName, volume, NULL, NULL, TRUE, FALSE, kHFSRootFolderID);

            if(!record)
            {
                newFile(fullName, volume);
                record = (HFSPlusCatalogFile*) getRecordFromPath(fullName, volume, NULL, NULL);
                if(record)
                {
                    record->permissions.fileMode |= S_IFLNK;
                    record->userInfo.fileType = kSymLinkFileType;
                    record->userInfo.fileCreator = kSymLinkCreator;
                    updateCatalog(volume, (HFSPlusCatalogRecord*) record);

                    io = openRawFile(record->fileID, &record->dataFork, (HFSPlusCatalogRecord*) record, volume);

                    char target[1024 + 1] = {'\0'};
                    int rv = readlink(ent->d_name, target, 1024);

                    printf("file link: %s %s\n", ent->d_name, target);	fflush(stdout);

                    if (rv != -1)
                    {
                        WRITE(io, 0, strlen(target), (void*) target);
                    }
                    CLOSE(io);
                }
            }


            free(record);

        }
        else if((tmp = opendir(ent->d_name)) != NULL) {
			closedir(tmp);
			printf("folder: %s\n", fullName); fflush(stdout);

			if(cnid == 0) {
				cnid = newFolder(fullName, volume);
			}

			fullName[pathLen] = '/';
			fullName[pathLen + 1] = '\0';
			ASSERT(chdir(ent->d_name) == 0, "chdir");
			addAllInFolder(cnid, volume, fullName);
			ASSERT(chdir(cwd) == 0, "chdir");
		} else {
			printf("file: %s\n", fullName);	fflush(stdout);
			if(cnid == 0) {
				cnid = newFile(fullName, volume);
			}
			file = createAbstractFileFromFile(fopen(ent->d_name, "rb"));
			ASSERT(file != NULL, "fopen");
			outFile = (HFSPlusCatalogFile*)getRecordByCNID(cnid, volume);
			writeToHFSFile(outFile, file, volume);
			file->close(file);
			free(outFile);

            /* Copy permissions from the source file */
            struct stat st;
            ASSERT (lstat(ent->d_name, &st) == 0, "lstat");
            chmodFile(fullName, (int)st.st_mode, volume);
            printf("Setting permissions to %06o for %s\n", st.st_mode, fullName);

			if(strncmp(fullName, "/Applications/", sizeof("/Applications/") - 1) == 0) {
				testBuffer[0] = '\0';
				strcpy(testBuffer, "/Applications/");
				strcat(testBuffer, ent->d_name);
				strcat(testBuffer, ".app/");
				strcat(testBuffer, ent->d_name);
				if(strcmp(testBuffer, fullName) == 0) {
					if(strcmp(ent->d_name, "Installer") == 0
					|| strcmp(ent->d_name, "BootNeuter") == 0
					) {
						printf("Giving setuid permissions to %s...\n", fullName); fflush(stdout);
						chmodFile(fullName, 04755, volume);
					} else {
						printf("Giving permissions to %s\n", fullName); fflush(stdout);
						chmodFile(fullName, 0755, volume);
					}
				}
			} else if(strncmp(fullName, "/bin/", sizeof("/bin/") - 1) == 0
				|| strncmp(fullName, "/Applications/BootNeuter.app/bin/", sizeof("/Applications/BootNeuter.app/bin/") - 1) == 0
				|| strncmp(fullName, "/sbin/", sizeof("/sbin/") - 1) == 0
				|| strncmp(fullName, "/usr/sbin/", sizeof("/usr/sbin/") - 1) == 0
				|| strncmp(fullName, "/usr/bin/", sizeof("/usr/bin/") - 1) == 0
				|| strncmp(fullName, "/usr/libexec/", sizeof("/usr/libexec/") - 1) == 0
				|| strncmp(fullName, "/usr/local/bin/", sizeof("/usr/local/bin/") - 1) == 0
				|| strncmp(fullName, "/usr/local/sbin/", sizeof("/usr/local/sbin/") - 1) == 0
				|| strncmp(fullName, "/usr/local/libexec/", sizeof("/usr/local/libexec/") - 1) == 0
				) {
				chmodFile(fullName, 0755, volume);
				printf("Giving permissions to %s\n", fullName); fflush(stdout);
			}
		}
	}

	closedir(dir);

	releaseCatalogRecordList(theList);
}

void extractAllInFolder(HFSCatalogNodeID folderID, Volume* volume) {
	CatalogRecordList* list;
	CatalogRecordList* theList;
	char cwd[1024];
	char* name;
	HFSPlusCatalogFolder* folder;
	HFSPlusCatalogFile* file;
	AbstractFile* outFile;
	struct stat status;

	ASSERT(getcwd(cwd, 1024) != NULL, "cannot get current working directory");

	theList = list = getFolderContents(folderID, volume);

	while(list != NULL) {
		name = unicodeToAscii(&list->name);
		if(strncmp(name, ".HFS+ Private Directory Data", sizeof(".HFS+ Private Directory Data") - 1) == 0 || name[0] == '\0') {
			free(name);
			list = list->next;
			continue;
		}

		if(list->record->recordType == kHFSPlusFolderRecord) {
			folder = (HFSPlusCatalogFolder*)list->record;
			printf("folder: %s\n", name);
			if(stat(name, &status) != 0) {
				ASSERT(mkdir(name, 0755) == 0, "mkdir");
			}
			ASSERT(chdir(name) == 0, "chdir");
			extractAllInFolder(folder->folderID, volume);
			ASSERT(chdir(cwd) == 0, "chdir");
		} else if(list->record->recordType == kHFSPlusFileRecord) {
			printf("file: %s\n", name);
			file = (HFSPlusCatalogFile*)list->record;
			outFile = createAbstractFileFromFile(fopen(name, "wb"));
			if(outFile != NULL) {
				writeToFile(file, outFile, volume);
				outFile->close(outFile);
			} else {
				printf("WARNING: cannot fopen %s\n", name);
			}
		}

		free(name);
		list = list->next;
	}
	releaseCatalogRecordList(theList);
}


void addall_hfs(Volume* volume, const char* dirToMerge, const char* dest) {
	HFSPlusCatalogRecord* record;
	char* name;
	char cwd[1024];
	char initPath[1024];
	int lastCharOfPath;

	ASSERT(getcwd(cwd, 1024) != NULL, "cannot get current working directory");

	if(chdir(dirToMerge) != 0) {
		printf("Cannot open that directory: %s\n", dirToMerge);
		exit(0);
	}

	record = getRecordFromPath(dest, volume, &name, NULL);
	strcpy(initPath, dest);
	lastCharOfPath = strlen(dest) - 1;
	if(dest[lastCharOfPath] != '/') {
		initPath[lastCharOfPath + 1] = '/';
		initPath[lastCharOfPath + 2] = '\0';
	}

	if(record != NULL) {
		if(record->recordType == kHFSPlusFolderRecord)
			addAllInFolder(((HFSPlusCatalogFolder*)record)->folderID, volume, initPath);
		else {
			printf("Not a folder\n");
			exit(0);
		}
	} else {
		printf("No such file or directory\n");
		exit(0);
	}

	ASSERT(chdir(cwd) == 0, "chdir");
	free(record);

}

int copyAcrossVolumes(Volume* volume1, Volume* volume2, char* path1, char* path2) {
	void* buffer;
	size_t bufferSize;
	AbstractFile* tmpFile;
	int ret;

	buffer = malloc(1);
	bufferSize = 0;
	tmpFile = createAbstractFileFromMemoryFile((void**)&buffer, &bufferSize);

	if(!silence)
	{
		printf("retrieving... "); fflush(stdout);
	}

	get_hfs(volume1, path1, tmpFile);
	tmpFile->seek(tmpFile, 0);

	if(!silence)
	{
		printf("writing (%ld)... ", (long) tmpFile->getLength(tmpFile)); fflush(stdout);
	}

	ret = add_hfs(volume2, tmpFile, path2);

	if(!silence)
	{
		printf("done\n");
	}

	free(buffer);

	return ret;
}

void displayFolder(HFSCatalogNodeID folderID, Volume* volume) {
	CatalogRecordList* list;
	CatalogRecordList* theList;
	HFSPlusCatalogFolder* folder;
	HFSPlusCatalogFile* file;
	time_t fileTime;
	struct tm *date;
	HFSPlusDecmpfs* compressData;
	size_t attrSize;

	theList = list = getFolderContents(folderID, volume);

	while(list != NULL) {
		if(list->record->recordType == kHFSPlusFolderRecord) {
			folder = (HFSPlusCatalogFolder*)list->record;
			printf("%06o ", folder->permissions.fileMode);
			printf("%3d ", folder->permissions.ownerID);
			printf("%3d ", folder->permissions.groupID);
			printf("%12d ", folder->valence);
			fileTime = APPLE_TO_UNIX_TIME(folder->contentModDate);
		} else if(list->record->recordType == kHFSPlusFileRecord) {
			file = (HFSPlusCatalogFile*)list->record;
			printf("%06o ", file->permissions.fileMode);
			printf("%3d ", file->permissions.ownerID);
			printf("%3d ", file->permissions.groupID);
			if(file->permissions.ownerFlags & UF_COMPRESSED) {
				attrSize = getAttribute(volume, file->fileID, "com.apple.decmpfs", (uint8_t**)(&compressData));
				flipHFSPlusDecmpfs(compressData);
				printf("%12" PRId64 " ", compressData->size);
				free(compressData);
			} else {
				printf("%12" PRId64 " ", file->dataFork.logicalSize);
			}
			fileTime = APPLE_TO_UNIX_TIME(file->contentModDate);
		}

		date = localtime(&fileTime);
		if(date != NULL) {
			printf("%2d/%2d/%4d %02d:%02d ", date->tm_mon, date->tm_mday, date->tm_year + 1900, date->tm_hour, date->tm_min);
		} else {
			printf("                 ");
		}

		printUnicode(&list->name);
		printf("\n");

		list = list->next;
	}

	releaseCatalogRecordList(theList);
}

void displayFileLSLine(Volume* volume, HFSPlusCatalogFile* file, const char* name) {
	time_t fileTime;
	struct tm *date;
	HFSPlusDecmpfs* compressData;

	printf("%06o ", file->permissions.fileMode);
	printf("%3d ", file->permissions.ownerID);
	printf("%3d ", file->permissions.groupID);

	if(file->permissions.ownerFlags & UF_COMPRESSED) {
		getAttribute(volume, file->fileID, "com.apple.decmpfs", (uint8_t**)(&compressData));
		flipHFSPlusDecmpfs(compressData);
		printf("%12" PRId64 " ", compressData->size);
		free(compressData);
	} else {
		printf("%12" PRId64 " ", file->dataFork.logicalSize);
	}

	fileTime = APPLE_TO_UNIX_TIME(file->contentModDate);
	date = localtime(&fileTime);
	if(date != NULL) {
		printf("%2d/%2d/%4d %2d:%02d ", date->tm_mon, date->tm_mday, date->tm_year + 1900, date->tm_hour, date->tm_min);
	} else {
		printf("                 ");
	}
	printf("%s\n", name);

	XAttrList* next;
	XAttrList* attrs = getAllExtendedAttributes(file->fileID, volume);
	if(attrs != NULL) {
		printf("Extended attributes\n");
		while(attrs != NULL) {
			next = attrs->next;
			printf("\t%s\n", attrs->name);
			free(attrs->name);
			free(attrs);
			attrs = next;
		}
	}
}

void hfs_ls(Volume* volume, const char* path) {
	HFSPlusCatalogRecord* record;
	char* name;

	record = getRecordFromPath(path, volume, &name, NULL);

	printf("%s: \n", name);
	if(record != NULL) {
		if(record->recordType == kHFSPlusFolderRecord)
			displayFolder(((HFSPlusCatalogFolder*)record)->folderID, volume);
		else
			displayFileLSLine(volume, (HFSPlusCatalogFile*)record, name);
	} else {
		printf("No such file or directory\n");
	}

	printf("Total filesystem size: %lld, free: %lld\n", ((uint64_t)(volume->volumeHeader->totalBlocks - volume->volumeHeader->freeBlocks)) * volume->volumeHeader->blockSize, ((uint64_t)volume->volumeHeader->freeBlocks) * volume->volumeHeader->blockSize); // cast to uint64_t to be plateform independant.

	free(record);
}

/* Tar fields are fixed-width byte arrays, not C strings. */
#define TAR_PATH_SIZE 4096

static int tarNumber(const unsigned char* field, size_t length, uint64_t* value) {
	size_t i = 0;
	*value = 0;
	if(field[0] & 0x80) {
		/* GNU base-256, positive values only. */
		if(field[0] & 0x40) return FALSE;
		*value = field[0] & 0x3f;
		for(i = 1; i < length; i++) {
			if(*value > (UINT64_MAX - field[i]) / 256) return FALSE;
			*value = *value * 256 + field[i];
		}
		return TRUE;
	}
	while(i < length && field[i] == ' ') i++;
	for(; i < length && field[i] >= '0' && field[i] <= '7'; i++) {
		if(*value > (UINT64_MAX - (field[i] - '0')) / 8) return FALSE;
		*value = *value * 8 + field[i] - '0';
	}
	for(; i < length; i++)
		if(field[i] != 0 && field[i] != ' ') return FALSE;
	return TRUE;
}

static int tarRead(AbstractFile* file, off_t offset, void* data, size_t size) {
	return file->seek(file, offset) == 0 && file->read(file, data, size) == size;
}

static void tarString(char* dest, const unsigned char* field, size_t size) {
	size_t length = 0;
	while(length < size && field[length]) length++;
	memcpy(dest, field, length);
	dest[length] = 0;
}

/* Reject traversal and components that overflow the catalog's HFSUniStr255. */
static int tarPath(char* path) {
	char* src = path;
	char* dst = path;
	if(*src == '/') return FALSE;
	while(*src) {
		char* start;
		size_t length;
		while(*src == '/') src++;
		start = src;
		while(*src && *src != '/') src++;
		length = src - start;
		if(!length || (length == 1 && start[0] == '.')) continue;
		if(length > 255 || (length == 2 && start[0] == '.' && start[1] == '.')) return FALSE;
		if(dst != path) *dst++ = '/';
		memmove(dst, start, length);
		dst += length;
	}
	*dst = 0;
	return TRUE;
}

/* Check every parent without following symlinks, including links in the image. */
static int tarParents(char* path, Volume* volume) {
	char* p;
	for(p = path; *p; p++) {
		HFSPlusCatalogRecord* record;
		if(*p != '/') continue;
		*p = 0;
		record = getRecordFromPath3(path, volume, NULL, NULL, FALSE, FALSE, kHFSRootFolderID);
		if(!record) {
			if(!newFolder(path, volume)) { *p = '/'; return FALSE; }
		} else if(record->recordType != kHFSPlusFolderRecord) {
			free(record);
			*p = '/';
			return FALSE;
		}
		free(record);
		*p = '/';
	}
	return TRUE;
}

/* Unlike add_hfs, keep write/allocation errors in the checked tar API. */
static int tarWrite(Volume* volume, const char* name, FILE* data, const char* target, off_t size) {
	HFSPlusCatalogFile* record;
	io_func* io;
	unsigned char buffer[65536];
	off_t offset = 0;
	int result;
	if(!newFile(name, volume)) return FALSE;
	record = (HFSPlusCatalogFile*)getRecordFromPath3(name, volume, NULL, NULL, FALSE, FALSE, kHFSRootFolderID);
	if(!record) return FALSE;
	io = openRawFile(record->fileID, &record->dataFork, (HFSPlusCatalogRecord*)record, volume);
	if(!io) {
		free(record);
		removeFile(name, volume);
		return FALSE;
	}
	result = allocate((RawFile*)io->data, size);
	while(result && offset < size) {
		size_t count = (uint64_t)(size - offset) > sizeof(buffer) ? sizeof(buffer) : (size_t)(size - offset);
		if(data) {
			result = fread(buffer, 1, count, data) == count;
		} else {
			memcpy(buffer, target + offset, count);
		}
		if(result) result = WRITE(io, offset, count, buffer);
		offset += count;
	}
	CLOSE(io);
	free(record);
	if(!result) removeFile(name, volume);
	return result;
}

static int tarExtract(Volume* volume, char* name, const char* target, char type,
		uint64_t mode, uint64_t uid, uint64_t gid, FILE* data, off_t size) {
	HFSPlusCatalogRecord* record;
	HFSPlusBSDInfo* permissions;
	int exists;
	if(!tarParents(name, volume)) return FALSE;
	record = getRecordFromPath3(name, volume, NULL, NULL, FALSE, FALSE, kHFSRootFolderID);
	exists = record != NULL;
	if(record && (record->recordType == kHFSPlusFolderRecord || type == '5')) {
		int compatible = record->recordType == kHFSPlusFolderRecord && type == '5';
		if(!compatible) { free(record); return FALSE; }
	}
	if(type != '5') {
		uint64_t blockSize = volume->volumeHeader->blockSize;
		uint64_t available = volume->volumeHeader->freeBlocks;
		if(type == '2') size = (off_t)strlen(target);
		if(record && record->recordType == kHFSPlusFileRecord) {
			available += ((HFSPlusCatalogFile*)record)->dataFork.totalBlocks;
			available += ((HFSPlusCatalogFile*)record)->resourceFork.totalBlocks;
		}
		if(size < 0 || !blockSize || (uint64_t)size / blockSize + ((uint64_t)size % blockSize != 0) > available) {
			free(record);
			return FALSE;
		}
	}
	free(record);
	if(type == '5') {
		if(!exists && !newFolder(name, volume)) return FALSE;
	} else {
		if(exists && !removeFile(name, volume)) return FALSE;
		if(!tarWrite(volume, name, data, target, size)) return FALSE;
	}
	record = getRecordFromPath3(name, volume, NULL, NULL, FALSE, FALSE, kHFSRootFolderID);
	if(!record) return FALSE;
	if(record->recordType == kHFSPlusFolderRecord) {
		permissions = &((HFSPlusCatalogFolder*)record)->permissions;
	} else if(record->recordType == kHFSPlusFileRecord) {
		HFSPlusCatalogFile* file = (HFSPlusCatalogFile*)record;
		permissions = &file->permissions;
		if(type == '2') {
			permissions->fileMode = S_IFLNK;
			file->userInfo.fileType = kSymLinkFileType;
			file->userInfo.fileCreator = kSymLinkCreator;
		}
	} else { free(record); return FALSE; }
	/* Updating the record directly also handles dangling links and never chmods their targets. */
	permissions->fileMode = (permissions->fileMode & S_IFMT) | (mode & 07777);
	permissions->ownerID = uid;
	permissions->groupID = gid;
	{
		int result = updateCatalog(volume, record);
		free(record);
		return result;
	}
}

/* First pass validates the whole archive before any image changes. The second
 * stages each regular file on disk before replacing an existing catalog entry. */
static int tarPass(Volume* volume, AbstractFile* tarFile, int extract) {
	off_t length = tarFile->getLength(tarFile);
	uint64_t offset = 0;
	char longName[TAR_PATH_SIZE] = {0};
	char longLink[1024] = {0};
	int haveName = FALSE, haveLink = FALSE;
	if(length < 0 || (uint64_t)length % 512) return FALSE;
	while(offset < (uint64_t)length) {
		unsigned char block[512];
		unsigned char buffer[65536];
		char name[TAR_PATH_SIZE], target[1024];
		uint64_t size, mode, uid, gid, checksum, padded, pos;
		unsigned int sum = 0;
		int signedSum = 0;
		size_t i;
		char type;
		FILE* staging = NULL;
		if((uint64_t)length - offset < 512 || !tarRead(tarFile, (off_t)offset, block, 512)) return FALSE;
		for(i = 0; i < 512 && !block[i]; i++) { }
		if(i == 512) {
			if(haveName || haveLink || (uint64_t)length - offset < 1024) return FALSE;
			/* Require the two end blocks and only zero padding thereafter. */
			for(pos = offset + 512; pos < (uint64_t)length;) {
				size_t count = (uint64_t)length - pos > sizeof(buffer) ? sizeof(buffer) : (size_t)((uint64_t)length - pos);
				if(!tarRead(tarFile, (off_t)pos, buffer, count)) return FALSE;
				for(i = 0; i < count; i++) if(buffer[i]) return FALSE;
				pos += count;
			}
			return TRUE;
		}
		if(!tarNumber(block + 148, 8, &checksum)) return FALSE;
		for(i = 0; i < 512; i++) {
			unsigned char c = i >= 148 && i < 156 ? ' ' : block[i];
			sum += c;
			signedSum += (signed char)c;
		}
		if(checksum != sum && (signedSum < 0 || checksum != (uint64_t)signedSum)) return FALSE;
		if(!tarNumber(block + 124, 12, &size) ||
		   !tarNumber(block + 100, 8, &mode) || mode > 07777 ||
		   !tarNumber(block + 108, 8, &uid) || uid > UINT32_MAX ||
		   !tarNumber(block + 116, 8, &gid) || gid > UINT32_MAX) return FALSE;
		if(size > (uint64_t)length - offset - 512) return FALSE;
		padded = size + ((512 - size % 512) % 512);
		if(padded < size || padded > (uint64_t)length - offset - 512) return FALSE;
		type = block[156] ? block[156] : '0';
		if(type == 'L' || type == 'K') {
			char* dest = type == 'L' ? longName : longLink;
			size_t capacity = type == 'L' ? sizeof(longName) : sizeof(longLink);
			if(!size || size > capacity || (type == 'L' ? haveName : haveLink)) return FALSE;
			if(!tarRead(tarFile, (off_t)(offset + 512), dest, (size_t)size) || dest[size - 1] != 0 ||
			   memchr(dest, 0, (size_t)size - 1)) return FALSE;
			if(type == 'L') haveName = TRUE; else haveLink = TRUE;
			offset += 512 + padded;
			continue;
		}
		/* Fail explicitly for PAX, hardlinks, sparse files and special files. */
		if(type != '0' && type != '2' && type != '5') return FALSE;
		if(type != '0' && size) return FALSE;
		if(haveLink && type != '2') return FALSE;
		tarString(name, block, 100);
		if(!haveName && !memcmp(block + 257, "ustar\0", 6) && block[345]) {
			char prefix[156], base[101];
			tarString(prefix, block + 345, 155);
			tarString(base, block, 100);
			snprintf(name, sizeof(name), "%s/%s", prefix, base);
		} else if(haveName) {
			strcpy(name, longName);
		}
		tarString(target, block + 157, 100);
		if(haveLink) strcpy(target, longLink);
		haveName = haveLink = FALSE;
		if(!name[0] || !tarPath(name) || (!name[0] && type != '5') ||
		   (type == '2' && !target[0])) return FALSE;
		if(extract && type == '0') {
			staging = tmpfile();
			if(!staging) return FALSE;
		}
		for(pos = 0; pos < size;) {
			size_t count = size - pos > sizeof(buffer) ? sizeof(buffer) : (size_t)(size - pos);
			if(!tarRead(tarFile, (off_t)(offset + 512 + pos), buffer, count) ||
			   (staging && fwrite(buffer, 1, count, staging) != count)) {
				if(staging) fclose(staging);
				return FALSE;
			}
			pos += count;
		}
		if(staging && (fflush(staging) || fseeko(staging, 0, SEEK_SET))) {
			fclose(staging);
			return FALSE;
		}
		if(extract && name[0] && !tarExtract(volume, name, target, type, mode, uid, gid, staging, (off_t)size)) {
			fprintf(stderr, "untar: cannot extract %s\n", name);
			if(staging) fclose(staging);
			return FALSE;
		}
		if(staging) fclose(staging);
		offset += 512 + padded;
	}
	return FALSE; /* Missing end-of-archive marker. */
}

int hfs_untar_checked(Volume* volume, AbstractFile* tarFile) {
	if(!volume || !tarFile || !tarFile->getLength || !tarFile->read || !tarFile->seek ||
	   !tarPass(volume, tarFile, FALSE)) {
		fprintf(stderr, "untar: invalid, truncated, or unsupported archive\n");
		return FALSE;
	}
	if(!tarPass(volume, tarFile, TRUE)) {
		fprintf(stderr, "untar: extraction failed\n");
		return FALSE;
	}
	return TRUE;
}

void hfs_untar(Volume* volume, AbstractFile* tarFile) {
	(void)hfs_untar_checked(volume, tarFile);
}
