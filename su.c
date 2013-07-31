/*
** SimpleSU
** 2012, 2013 n0p
** Ecological - contains 50% recycled code :)
** Some credit would be nice if you use it.
*/

#define LOG_TAG "SimpleSU"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <android/log.h>

#define SUDEBUG 0

#define APPNAMELEN 64

#define APPNUMBER 128

#define INSECURE 1

#ifdef INSECURE
#define VERSION "v0.7.Insecure"
#else
#define VERSION "v0.7"
#endif

char parameters[128];

#ifndef INSECURE
pid_t p_pid;
char p_name[APPNAMELEN];
char app_name[APPNAMELEN];
char skip[32];

int app_number = 0;

int allow_access = 0;

//n0p - 128 entries should be enough
char su_list[APPNUMBER][APPNAMELEN];

char su_config[]="/system/etc/dsc.su_list";

int parent_pid_info(pid_t pid)
{
    char proc_path[32];
    FILE *proc_file;

    snprintf(proc_path, 32, "/proc/%u/stat", pid);
    proc_file = fopen(proc_path, "r");
    if (proc_file < 0) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Error openinig stat for %u\n",pid);
        return 0;
    }
    fscanf(proc_file, "%*d %64s %*c %u", p_name, &p_pid);
    fclose(proc_file);

    snprintf(proc_path, 32, "/proc/%u/cmdline", p_pid);
    proc_file = fopen(proc_path, "r");
    if (proc_file < 0) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Error openinig cmdline for %u\n",p_pid);
        return 0;
    }
    fscanf(proc_file, "%64s", app_name);
    fclose(proc_file);

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Checking %s\n",app_name);

    return 1;
}

int first_pid_info(pid_t pid)
{
    char proc_path[32];
    FILE *proc_file;

    snprintf(proc_path, 32, "/proc/%u/cmdline", p_pid);
    proc_file = fopen(proc_path, "r");
    if (proc_file < 0) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Error openinig cmdline for %u\n",pid);
        return 0;
    }
    fscanf(proc_file, "%64s", app_name);
    fclose(proc_file);

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Checking %s\n",app_name);

    return 1;
}

int check_access()
{
int i;
char service_name[APPNAMELEN];
  for (i=0;i<app_number;i++) {
		snprintf(service_name, APPNAMELEN, "%s:", su_list[i]);
		if (!strncmp(app_name,service_name,strlen(service_name))) {
		__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Allow service %s\n",app_name);
		return 1; }
		 if (!strcmp(app_name,su_list[i])) {
                __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Allow %s\n",app_name);
                return 1; };
	}
return 0;
}
#endif

// n0p - this code should do for su UID and su -c
int main(int argc, char **argv)
{
    struct passwd *pw;
    int uid, gid, myuid, legacy;
    
    legacy = 0;

    if(argc < 2) {
        uid = gid = 0;
    } else {
	if (strcmp("-c",argv[1])) {
		legacy = 1;
	        pw = getpwnam(argv[1]);
		        if(pw == 0) {
			          uid = gid = atoi(argv[1]);
		        } else {
			            uid = pw->pw_uid;
			            gid = pw->pw_gid;
			        }
    	} else {
			uid = gid = 0;
	}
     }

int i;
for (i = 1; i < argc; i++) sprintf(parameters,"%s %s ",parameters,argv[i]);
__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", parameters);

#if SUDEBUG
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "SimpleSU %s (n0p, DSC Team) built %s %s\n",VERSION,__DATE__,__TIME__);
#endif
	printf("SimpleSU %s (n0p, DSC Team) built %s %s\n",VERSION,__DATE__,__TIME__);

#ifndef INSECURE

//n0p - read allowed list
	FILE *file = fopen(su_config,"r");
	if (!file) {
		__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "No config file.\n");
		return 1;
	};
//This cool snippet from Munawwar
	while(!feof(file)) {
		fscanf(file,"%[^ \n\t\r]s",&su_list[app_number]);
		fscanf(file,"%[ \n\t\r]s",&skip);
//-Munawwar
//n0p - i know we'll have one app even with empty whitelist, but it's ok.
                app_number++;
//Prevent overflow
		if (app_number >= APPNUMBER) {
			__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "More than %d entries in config file.\n",APPNUMBER);
			break;
		}
#if SUDEBUG
		 __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "+%s\n",&su_list[app_number-1]);
#endif
	};

//n0p - won't happen
    if (getppid()==0) {
	        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "No parent process. Quit.\n");
		return 1;
	} else p_pid=getppid();

//n0p - first check
    if (first_pid_info(p_pid)) {
        allow_access=check_access();
#if SUDEBUG
	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s: %u\n",app_name,allow_access);
#endif
    } else return 1;

//n0p - walk this tree
    if (!allow_access) {
	while (p_pid>1) {
	   if (parent_pid_info(p_pid)) {
	        allow_access=check_access();
		if (allow_access) break;
#if SUDEBUG
	        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s: %u\n",app_name,allow_access);
#endif
	   }
	}
    }

    if (!allow_access) {
	       __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Reject superuser request.\n");
	       return 1;
    };

#endif

    if(setgid(gid) || setuid(uid)) {
        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Permission denied\n");
        return 1;
    }

//ICS - ChainsDD
    setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 1);
    setegid(gid);
    seteuid(uid);
//won't hurt dunno if needed
    setenv("LD_LIBRARY_PATH", "/vendor/lib:/system/lib", 1);
//-ChainsDD

    if ( argc >=3 ) {   
                char *exec_args[argc + 1];
                memset(exec_args, 0, sizeof(exec_args));
//n0p - we got here with -c format, call converted to /system/bin/sh -c "make me a sandwich"
//Should do the trick for Android, even if it doesn't support full su functionality.
//Need to implement full su parameters set sometime
	if (!legacy) {
                exec_args[0] = "sh";
	        int i;
	        for (i = 1; i < argc; i++) exec_args[i] = argv[i];
                __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Executing: %s", argv[2]);
                if (execvp("/system/bin/sh", exec_args) < 0) {
                        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Exec failed for %s Error:%s\n", argv[2],
                             strerror(errno)); };
	} else {
//n0p - legacy Google Android format "su root make me a sandwich"
	    if ( argc == 3 ) {
                __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Executing legacy: %s", argv[2]);
        	if (execlp(argv[2], argv[2], NULL) < 0) {
                         __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Exec failed for %s Error:%s\n", argv[2],
                	   strerror(errno));
		            return -errno; };
	    } else {
	        memcpy(exec_args, &argv[2], sizeof(exec_args));
	        __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Executing legacy: %s", argv[2]);
	        if (execvp(argv[2], exec_args) < 0) {
			 __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Exec failed for %s Error:%s\n", argv[2],
	                    strerror(errno));
	            return -errno; }
           }
        }
    }

//Shell
    execlp("/system/bin/sh", "sh", NULL);

    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "Exec failed\n");
    return 1;
}
