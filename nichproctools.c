/*
 * Author: Nicholai Gallegos
 * CS373 HW2
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>

// list all the processes
void list_procs(char* dir_path) {
	struct dirent* ent = NULL;
	DIR* dir_ptr = NULL;

	// open the directory, check if it worked
	dir_ptr = opendir(dir_path);

	// directory exists
	if (dir_ptr != NULL) {
		// iterate through directory
		while ((ent = readdir(dir_ptr))) {
			char proc_id[256];
			// check if the entry name is a number, this is how we know it's a process ID
			if (sscanf(ent->d_name, "%d", proc_id) != 0) {
				int pid;
				uid_t user_id;
				struct stat proc_stat;
				struct passwd* user_info;

				char curr_dir[256];
				char comm[256];  // the name of the program from /proc/[pid]/stat
				memset(curr_dir, '\0', 256);

				strcat(curr_dir, dir_path);
				strcat(curr_dir, ent->d_name);
				strcat(curr_dir, "/stat");
			
				// make a stat call to find the user id, then use th passwd struct to get
				// the username
				stat(curr_dir, &proc_stat);
				user_id = proc_stat.st_uid;
				user_info = getpwuid(user_id);

				// fscanf through the stat file to get pid, command line string
				FILE* fd = fopen(curr_dir, "r");
				fscanf(fd, "%d %s", &pid, comm);
				fclose(fd);
				printf("PID: %d	| User: %s | Process: %s\n", pid, user_info->pw_name, comm);	
			}
		}
	}
	closedir(dir_ptr);
}

// list all the threads for a process
void list_threads(char* pid) {
	struct dirent* ent = NULL;
	DIR* dir_ptr = NULL;
	char dir_path[256];
	memset(dir_path, '\0', 256);

	// look in the tasks directory for threads associated with process
	strcat(dir_path, "/proc/");
	strcat(dir_path, pid);
	strcat(dir_path, "/task/");
	
	dir_ptr = opendir(dir_path);
	
	if (dir_ptr != NULL) {
		printf("%s", "Threads for: ");
		// print every process name of the threads found in the /task directory
		while ((ent = readdir(dir_ptr))) {
			if (strcmp(ent->d_name, ".") != 0) {
				int thread_pid;

				char thread_dir_name[256];
				char comm[256];
				memset(thread_dir_name, '\0', 256);
				memset(comm, '\0', 256);
			
				strcat(thread_dir_name, dir_path);
				strcat(thread_dir_name, ent->d_name);
				strcat(thread_dir_name, "/stat");

				FILE* fd = fopen(thread_dir_name, "r");
				fscanf(fd, "%d %s", &thread_pid, comm);
				fclose(fd);

				printf("PID: %d | Process: %s\n", thread_pid, comm);
			}
		}
		closedir(dir_ptr);	
	}
	else {
		printf("Process %s not found\n", pid);
	}
}

void list_modules(char* pid) {
	char maps_path[256];
	memset(maps_path, '\0', 256);

	// generate the string to the maps file to see the memory pages
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char mem_range[256], junk_2[256], junk_3[256], junk_4[256];
		char perms[256], module[256];

		// for getline
		char* line = NULL;
		size_t len = 0;
		ssize_t nread;

		// get a line from the maps file, read the whitespace separated values into
		// the appropriate values (we only care about the module string here), then 
		// check if it contains the .so* extension
		while ((nread = getline(&line, &len, fd)) != -1) {
			sscanf(line, "%s %s %s %s %s %s", mem_range, perms, junk_2, junk_3, junk_4, module);
			
			// check if the ".so" file extension exists in the module string
			if (strstr(module, ".so") != NULL) {
				printf("address range: %s  |  module: [%s]  |  permissions: [%s]\n", mem_range, module, perms);
			}
		}
		free(line);
		fclose(fd);
	}
	else {
		printf("%s", "Process not found\n");
	}
}

/* Name: list_executable_pages
 * Desc: Lists the pages within the maps file with the "x" bit set in the
 * permissions.  This works almost exactly the same as list_modules except
 * it justs checks that the perms string has a 'x' in it.
 *
 */
void list_executable_pages(char* pid) {
	char maps_path[256];
	memset(maps_path, '\0', 256);

	// generate the string to the maps file to see the memory pages
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char mem_range[256], junk_2[256], junk_3[256], junk_4[256];
		char perms[256], module[256];

		// for getline
		char* line = NULL;
		size_t len = 0;
		ssize_t nread;

		/* get a line from the maps file, read the whitespace separated values into
		*  the appropriate values.  For this function we care about the perms string
		*  and we want to print the module associated with it (on the same line
		* from getline
		*/
		while ((nread = getline(&line, &len, fd)) != -1) {
			sscanf(line, "%s %s %s %s %s %s", mem_range, perms, junk_2, junk_3, junk_4, module);
			
			// check if "x" exists in the module string
			if (strstr(perms, "x") != NULL) {
				printf("address range: %s  |  module: [%s]  |  permissions: [%s]\n", mem_range, module, perms);
			}
		}
		free(line);
		fclose(fd);
	}
	else {
		printf("%s", "Process not found\n");
	}
}

/*read a memory address from the range provided.  This uses the memory listed
* by the pages in the maps file for the process.  Specified by the mem_search_start
* and mem_search_end.  These is the address range of the memory we want to examine.
* If this memory range doesn't exist within the memory of a single page (this does
* not search accross pages) then nothing will be printed
*/
void read_mem(char* pid, long int mem_search_start, long int mem_search_end) {
	char mem_path[256], maps_path[256];
	memset(mem_path, '\0', 256);
	memset(maps_path, '\0', 256);

	// generate the string to the mem file for later reference
	strcat(mem_path, "/proc/");
	strcat(mem_path, pid);
	strcat(mem_path, "/mem");
	// generate the string to the maps file to see the memory pages
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	//int fd = open(mem_path, O_RDONLY);
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char mem_range[256], mem_start[256], mem_end[256], junk_1[256], junk_2[256], junk_3[256];
		char perms[256], module[256];

		//for memory offsets
		long int low;
		long int high;

		// for getline
		char* line = NULL;
		size_t len = 0;
		ssize_t nread;

		/* get a line from the maps file, read the whitespace separated values into
		*  the appropriate values.  We want the memory range from the pages provided
		*  on each of the lines.  Note: this will only return a memory address if it is:
		*  1. a readable page and 2. there is a page that has the specified memory range
		*  within it's addresses.  This means it will not search accross pages, since 
		*  pages are not guaranteed to be contiguous!
		*/
		while ((nread = getline(&line, &len, fd)) != -1) {
			sscanf(line, "%s %s %s %s %s %s", mem_range, perms, junk_1, junk_2, junk_3, module);
			
			char *separator = strstr(mem_range, "-");
			// copy the last value of the range from the separtor onwards, add 1 to pointer
			// so the '-' isn't included
			strcpy(mem_end, separator + 1); 
			*separator = '\0'; // set to null terminator so we can separate the string
			strcpy(mem_start, mem_range); // copy the first part of the range now that the end has been "cut off"

			// convert the provided parameters from a string to an int to use with lseek, read
			low = strtol(mem_start, NULL, 16);
			high = strtol(mem_end, NULL, 16);
			
			// check if the memory address requested is within the current examined page
			if ((mem_search_start >= low) && (mem_search_end <= high)){
				char* buffer = (char*) malloc((mem_search_end - mem_search_start) * sizeof(char));

				int mem_fd = open(mem_path, O_RDONLY);
				lseek(mem_fd, mem_search_start, SEEK_SET);


				read(mem_fd, buffer, mem_search_end - mem_search_start);
	
				printf("memory contents: %s\n", buffer);
				close(mem_fd);
				free(buffer);
			}
		}
		
		free(line);
		fclose(fd);
	}

	
	else {
		printf("%s", "Process not found\n");
	}
}

void help_page() {
	printf("***NOTE*** - May require sudo permission to function properly\n");
	printf("Usage: ./nichproctools [option] args ...\n\n");
		
	printf("-ps | list processes\n");
	printf("usage: ./nichproctools -ps -- lists all processes with PID in proc filesystem\n\n");
	
	printf("-t | list threads for a process\n");
	printf("usage: ./nichproctools -t [PID]\n");
	printf("ex: ./nichproctools -t 1322 -- list threads in process 132\n\n");
	
	printf("-lm | list loaded modules for a process\n");
	printf("usage: ./nichproctools -lm [PID]\n");
	printf("ex: ./nichproctools -lm 1111 -- list modules for process 1111\n\n");

	printf("-ep | list executable pages for a process\n");
	printf("usage: ./nichproctools -ep [PID]\n");
	printf("ex: ./nichproctools -ep 1234 -- list executable pages for process 1234\n\n");

	printf("-m | read memory for a process\n");
	printf("usage: ./nichproctools -m [PID] [low memory address] [high memory address]\n");
	printf("ex: ./nichproctools -m 1221 ff80 ffd4 -- read memory for process 1221 from address 0xff80 to 0xffd4\n");
	printf("**NOTE** - please use the memory addresses found in the 'address' field of the maps file, these\n");
	printf("are the addresses displayed when using the -lm or -ep options\n");
}

int main(int argc, char** argv) {
	if (argc < 2) {
		printf("%s\n", "Too few arguments, try --help for all options");
	}

	else {
		if (argc == 2) {
			if (strcmp(argv[1], "-ps") == 0) {
				list_procs("/proc/");
			}
			else if ((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0)) {
				help_page();
			}
		}
		else if (argc == 3) {
			if (strcmp(argv[1], "-t") == 0) {
				list_threads(argv[2]);		
			}
			else if (strcmp(argv[1], "-lm") == 0) {
				list_modules(argv[2]);
			}
			else if (strcmp(argv[1], "-ep") == 0) {
				list_executable_pages(argv[2]);
			}
			//else if (strcmp(argv[1], "-m") == 0) {
			//	read_mem(argv[2]);
			//}
		}
		else if (argc == 5) {
			if (strcmp(argv[1], "-m") == 0) {
				long int low_mem_addr = strtol(argv[3], NULL, 16);
				long int high_mem_addr = strtol(argv[4], NULL, 16);
				read_mem(argv[2], low_mem_addr, high_mem_addr);
			}	
		}
	
	}

	return 0;
}
