#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>

#define SECONDS_PER_DAY		86400

int generateFromFile(char*);
int generateFromUserInput();
int generate(char*, char*, const char*, const char*);


int main(int argc, char *argv[]){

	if(argc == 2){
		return generateFromFile(argv[1]);
	}
	else{
		return generateFromUserInput();
	}
}

int generateFromFile(char* filename){
	const char *files[10] = {
		"./veryweak-passwd", "./veryweak-shadow",
		"./weak-passwd", "./weak-shadow",
		"./good-passwd", "./good-shadow",
		"./strong-passwd", "./strong-shadow",
		"./verystrong-passwd", "./verystrong-shadow"
	};
	char delim = '#';

	FILE *passwordFile = fopen(filename, "r");
	if(passwordFile == NULL){
		perror("fopen");
		return -1;
	}

	ssize_t nread;
	char *line;
	size_t len = 0;
	int fileIndex = -2;

	while((nread = getline(&line, &len, passwordFile)) != -1){
		if(line[0] == delim){
			fileIndex += 2;
			continue;
		}
		char *token;
		// Get the username
		token = strtok(line, ":");
		char username[32];
		sscanf(token, "%s", username);
		// Get the password
		token = strtok(NULL, ":");
		char password[256];
		sscanf(token, "%s", password);
		// Generate the password
		generate(username, password, files[fileIndex], files[fileIndex+1]);
	}

	free(line);
	fclose(passwordFile);
	return 0;
}

int generateFromUserInput(){
	// Get the username and passwords
	char username[32];
	printf("Enter username: ");
	fgets(username, 32, stdin);
	username[strcspn(username, "\n")] = 0;

	char password[128];
	printf("Enter password: ");
	fgets(password, 128, stdin);
	password[strcspn(password, "\n")] = 0;

	return generate(username, password, "./passwd", "./shadow");
}

int generate(char* username, char* password, const char* passwdFilename, const char* shadowFilename){
	// Create some fake password file data
	srand(time(NULL));
	int uid = 1000 + (rand() % 1000);
	int gid = 1000;// + (rand() % 1000);
	int createTime = time(NULL) / SECONDS_PER_DAY;
	int minPasswordChange = 0;
	int maxPasswordChange = 9999;
	int warnPasswordChange = 7;

	// Get paths to the files
	FILE *passwdFile = fopen(passwdFilename, "a");
	FILE *shadowFile = fopen(shadowFilename, "a");

	// Prepare the salt
	unsigned long seed[2];
	char salt[] = "$1$................";
	const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRST"
								  "UVWXYZabcdefghijklmnopqrstuvwxyz";
  	seed[0] = time(NULL);
  	seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);
  	int i;
	for (i = 0; i < 16; i++)
		salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

	// Generate the hash
	char* shadowPassword = crypt(password, salt);

	// Write information to the password file
	// username:password(x):uid:gid:info:home:shell
	fprintf(passwdFile, "%s:x:%d:%d:User information here:/home/%s:/bin/bash\n", 
		username, uid, gid, username);

	// Write information to the shadow file
	// user:password($scheme$salt$hash):creation:minchange:maxchange:warnchange:inactive:exire
	fprintf(shadowFile, "%s:%s:%d:%d:%d:%d:::\n", 
		username, shadowPassword, createTime, minPasswordChange, maxPasswordChange, 
		warnPasswordChange);

	// Be sure to close the files when done
	fclose(passwdFile);
	fclose(shadowFile);
}