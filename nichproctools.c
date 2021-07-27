#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>

int list_procs(char* dir_path) {
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

int list_threads(char* pid) {
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

int list_modules(char* pid) {
	char maps_path[256];
	memset(maps_path, '\0', 256);

	// generate the string to the maps file to see the memory pages
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char junk_1[256], junk_2[256], junk_3[256], junk_4[256];
		char perms[256], module[256];

		// for getline
		char* line = NULL;
		size_t len = 0;
		ssize_t nread;

		// get a line from the maps file, read the whitespace separated values into
		// the appropriate values (we only care about the module string here), then 
		// check if it contains the .so* extension
		while ((nread = getline(&line, &len, fd)) != -1) {
			sscanf(line, "%s %s %s %s %s %s", junk_1, perms, junk_2, junk_3, junk_4, module);
			
			// check if the ".so" file extension exists in the module string
			if (strstr(module, ".so") != NULL) {
				printf("module: %s\n", module);
			}
		}
		free(line);
		fclose(fd);
		return 0;		
	}
	else {
		printf("%s", "Process not found\n");
		return -1;
	}
}

/* Name: list_executable_pages
 * Desc: Lists the pages within the maps file with the "x" bit set in the
 * permissions.  This works almost exactly the same as list_modules except
 * it justs checks that the perms string has a 'x' in it.
 *
 */
int list_executable_pages(char* pid) {
	char maps_path[256];
	memset(maps_path, '\0', 256);

	// generate the string to the maps file to see the memory pages
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char junk_1[256], junk_2[256], junk_3[256], junk_4[256];
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
			sscanf(line, "%s %s %s %s %s %s", junk_1, perms, junk_2, junk_3, junk_4, module);
			
			// check if "x" exists in the module string
			if (strstr(perms, "x") != NULL) {
				printf("module: %s | permissions: %s\n", module, perms);
			}
		}
		free(line);
		fclose(fd);
		return 0;		
	}
	else {
		printf("%s", "Process not found\n");
		return -1;
	}
}

int read_mem(char* pid) {
	char mem_path[256], maps_path[256];
	memset(mem_path, '\0', 256);
	memset(maps_path, '\0', 256);

	// generate the string to the maps file to see the memory pages
	strcat(mem_path, "/proc/");
	strcat(mem_path, pid);
	strcat(mem_path, "/mem");
	strcat(maps_path, "/proc/");
	strcat(maps_path, pid);
	strcat(maps_path, "/maps");
	
	//int fd = open(mem_path, O_RDONLY);
	
	FILE* fd = fopen(maps_path, "r");	

	if (maps_path != NULL) {
		// will be useful for sscanf
		char mem_range[256], mem_start[256], mem_end[256], junk_1[256], junk_2[256], junk_3[256];
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
			sscanf(line, "%s %s %s %s %s %s", mem_range, perms, junk_1, junk_2, junk_3, module);
			
			char *separator = strstr(mem_range, "-");
			// copy the last value of the range from the separtor onwards, add 1 to pointer
			// so the '-' isn't included
			strcpy(mem_end, separator + 1); 
			*separator = '\0'; // set to null terminator so we can separate the string
			strcpy(mem_start, mem_range); // copy the first part of the range now that the end has been "cut off"

			// check if "x" exists in the module string
			//if (strstr(perms, "r") != NULL) {
				printf("memory start: %s | memory_end: %s | permissions: %s\n", mem_start, mem_end, perms);
			//}
		}
		free(line);
		fclose(fd);
		return 0;		
	}

	
#if 0
	if (fd != -1) {
		// will be useful for sscanf
		char mem_start[256], mem_end[256];// junk_3[256], junk_4[256];
		//char perms[256], module[256];

		// for getline
		//char* line = NULL;
		//size_t len = 0;
		//ssize_t nread;
		
		memset(junk_1, '\0', 256);

		while(read(fd, junk_1, 255) != -1) {
			printf("%s\n", junk_1);
		}
		/* get a line from the maps file, read the whitespace separated values into
		*  the appropriate values.  For this function we care about the perms string
		*  and we want to print the module associated with it (on the same line
		* from getline
		*/
		#if 0
		while ((nread = getline(&line, &len, fd)) != -1) {
			printf("%s\n", line);
			#if 0
			sscanf(line, "%s %s %s %s %s %s", junk_1, perms, junk_2, junk_3, junk_4, module);
			
			// check if "x" exists in the module string
			if (strstr(perms, "x") != NULL) {
				printf("module: %s | permissions: %s\n", module, perms);
			}
			#endif
		}
		free(line);
		#endif
		close(fd);
		return 0;		
	}
#endif
	else {
		printf("%s", "Process not found\n");
		return -1;
	}
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
			else if (strcmp(argv[1], "-m") == 0) {
				read_mem(argv[2]);
			}
		}
	
	}

	return 0;
}
