#include <stdio.h>

void random_string(char *str, int length);

int main () {
  char s[6] = "";
  random_string(s, 5);
  printf("%s\n", s);
  return 0;
}
