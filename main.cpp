#include <iostream>
#include "Parse.h"

int main(int argc, char **argv) {
    std::cout << "Hello, World!" << std::endl;
    Parse p;
    //input absolute path to file here
    string t = argv[1];
    p.doParse(t);
    p.detScan();
    return 0;
}
