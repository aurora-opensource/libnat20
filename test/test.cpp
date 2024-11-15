#include <iostream>
#include <gtest/gtest.h>

int main(int argc, char *argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    std::cout << "Testing libnat20..." << std::endl;
    int ret{RUN_ALL_TESTS()};
    if (!ret) {
        std::cout << "SUCCESS" << std::endl;
        return 0;
    } else {
        std::cout << "FAILURE" << std::endl;
        return -1;
    }
}
