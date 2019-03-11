#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NCOMMANDS 4

typedef void(*command_func_t)(char* params);
typedef struct command {
    command_func_t run;
    const char* name;
    const char* help;
} command_t;

void do_register( char* );
void do_login( char* );
void do_quit( char* );
void do_help( char* );
size_t read_string(char* s, size_t size);

// Encryption Key
char key[64] = {13,31,230,16,54,10,159,232,40,59,76,216,27,207,155,236,159,173,144,236,24,133,191,129,21,125,238,119,191,79,34,72,254,74,241,199,125,207,87,205,91,195,35,155,112,180,98,28,60,19,43,156,1,18,86,81,68,81,155,134,164,170,159,245};
// Username and (encrypted) password for authentication
char g_username[64] = {0,1};
char g_password[32] = {0,1};
command_t commands[NCOMMANDS] = {
    { .run = do_quit, .name = "quit", .help = "exit application" },
    { .run = do_help, .name = "help", .help = "print help menu" },
    { .run = do_register, .name = "register", .help = "register new user" },
    { .run = do_login, .name = "login", .help = "authenticate an existing user" }
};

int main(int argc, char** argv)
{
    char input[1024];
    size_t len;
    int i = 0;

    // Disable buffering on stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("*** Authentication Portal v1.5 (Beta) ***");
    puts("Type \"help\" for a list of commands");

    while( 1 )
    {
        // Read command
        printf("> ");
        len = read_string(input, 1024);

        // Ignore empty commands
        if( len == 0 ) continue;

        // Separate the input into the command and params
        char* cmd = strtok(input, " ");
        char* params = strtok(NULL, "\0");

        // Store the command we find
        command_func_t func = NULL;

        // Search for a matching command
        for(i = 0; i < NCOMMANDS; ++i){
            if( strcmp(commands[i].name, cmd) == 0 ){
                // Run the command
                commands[i].run(params);
                break;
            }
        }

        if( i == NCOMMANDS ){
            fprintf(stderr, "error: %s: invalid command (try 'help')\n", cmd);
        }
    }

    return 0;
}

size_t read_string(char* s, size_t size)
{
    fgets(s, size, stdin);
    size_t len = strlen(s);
    if( len > 0 && s[len-1] == '\n' ){
        s[--len] = 0;
    }
    return len;
}

void do_help( char* data )
{
    puts("available commands:");
    for(int i = 0; i < NCOMMANDS; ++i){
        printf("\t%s - %s\n", commands[i].name, commands[i].help);
    }
}

void do_register( char* parms )
{
    if( parms == NULL ){
        fprintf(stderr, "usage: register [username] [password]\n");
        return;
    }

    // Grab the username and password
    char* username = strtok(parms, " ");
    char* password = strtok(NULL, "\0");

    if( password == NULL ){
        fprintf(stderr, "error: no password specified\n");
        fprintf(stderr, "usage: register [username] [password]\n");
    }

    // copy the username into the global username variable
    strncpy(g_username, username, 64);

    // Don't store passwords in plaintext!
    for(size_t i = 0; i < strlen(password) && i < 64; ++i){
        g_password[i] = password[i] ^ key[i];
    }
}

void do_login( char* params )
{
    char* username, *password;

    if( params == NULL ){
        fprintf(stderr, "usage: login [username] [password]\n");
        return;
    }

    if( g_password[0] == 0 ){
        fprintf(stderr, "error: please register first.\n");
        return;
    }

    username = strtok(params, " ");
    password = strtok(NULL, "\0");

    if( password == NULL ){
        fprintf(stderr, "usage: login [username] [password]\n");
        return;
    }

    // Check username against password
    if( strcmp(username, g_username) != 0 ){
        fprintf(stderr, "error: user %s does not exist!\n", username);
        return;
    }

    // Encrypt password
    for(size_t i = 0; i < strlen(password) && i < 64; i++){
        password[i] ^= key[i];
    }

    // Check password against stored password
    if( strcmp(g_password, password) != 0 ){
        fprintf(stderr, "error: invalid password for user %s!\n", username);
    } else {
        printf("login successful! welcome %s.\n", username);
    }

}

void do_quit( char* params )
{
    puts("Clearing your credentials from memory...");
    for(size_t i = 0; i < 64; i++){
        g_username[i] = 0;
        g_password[i] = 0;
    }
    exit(0);
}