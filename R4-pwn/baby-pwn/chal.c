#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main() {
    // A value to keep track of whether you're an admin.
    int isadmin = 0;
    char username[20];

    printf("Please enter your name: ");
    //Read your input into the username array
    gets(username);

    //TODO: make it so if username matches an admin, we flip isadmin to 1
    //      For now it should just be 0 for everyone

    printf("Welcome %s, I'll just check if you're an admin\n", username);
    printf("The isadmin value is currently %d\n", isadmin);
    
    //Check whether isadmin is equal to 0
    if (isadmin == 0) {
        printf("You are not an admin, and so are not allowed my secret flag. Goodbye :)\n");
        return 0;
    }

    printf("you are an admin, how did you do that :o\nHere's your flag!\n**********redacted********\n");
    return 0;
}