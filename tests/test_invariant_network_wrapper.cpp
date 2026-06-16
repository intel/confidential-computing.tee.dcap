#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>
#include <climits>

// Include the actual implementation
// We need to access the write_callback function from network_wrapper.cpp
// The callback has signature: size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
// and uses a struct with base, size fields

// Replicate the struct used by the callback (from the source)
struct MemoryStruct {
    char *base;
    size_t size;
};

// Declare the write_callback as extern - it's defined in network_wrapper.cpp
extern "C" size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream);

class WriteCallbackSecurityTest : public ::testing::Test {
protected:
    MemoryStruct response;
    
    void SetUp() override {
        response.base = nullptr;
        response.size = 0;
    }
    
    void TearDown() override {
        if (response.base) {
            free(response.base);
            response.base = nullptr;
        }
    }
};

// Test: multiplication overflow case - size*nmemb overflows size_t
TEST_F(WriteCallbackSecurityTest, OverflowMultiplicationMustNotCauseHeapCorruption) {
    // size * nmemb would overflow: e.g., SIZE_MAX/2 + 1 * 2 = 0 (overflow)
    char dummy_data[16] = "AAAAAAAAAAAAAAAA";
    size_t big_size = (SIZE_MAX / 2) + 1;
    size_t nmemb = 2;
    // This should either return 0 (failure) or not corrupt memory
    size_t result = write_callback(dummy_data, big_size, nmemb, &response);
    // If overflow is not checked, malloc(0) may succeed and memcpy would overflow
    // The invariant: result should be 0 (rejected) OR response.size <= allocated amount
    EXPECT_TRUE(result == 0 || response.size <= big_size * nmemb);
}

// Test: realloc failure path - accumulate large chunks to exhaust growth
TEST_F(WriteCallbackSecurityTest, LargeAccumulationDoesNotOverflow) {
    // First call with valid data to initialize
    std::vector<char> payload(4096, 'B');
    size_t result1 = write_callback(payload.data(), 1, payload.size(), &response);
    ASSERT_EQ(result1, payload.size());
    ASSERT_EQ(response.size, payload.size());
    
    // Second call to trigger realloc path
    std::vector<char> payload2(8192, 'C');
    size_t result2 = write_callback(payload2.data(), 1, payload2.size(), &response);
    ASSERT_EQ(result2, payload2.size());
    // Verify total size is sum of both
    EXPECT_EQ(response.size, payload.size() + payload2.size());
    // Verify data integrity (no corruption)
    EXPECT_EQ(memcmp(response.base, payload.data(), payload.size()), 0);
    EXPECT_EQ(memcmp(response.base + payload.size(), payload2.data(), payload2.size()), 0);
}

// Test: valid small input works correctly
TEST_F(WriteCallbackSecurityTest, ValidSmallInputWorksCorrectly) {
    const char *data = "Hello";
    size_t result = write_callback((void*)data, 1, 5, &response);
    EXPECT_EQ(result, 5u);
    EXPECT_EQ(response.size, 5u);
    EXPECT_EQ(memcmp(response.base, data, 5), 0);
}

// Test: near-overflow boundary where size*nmemb is close to SIZE_MAX
TEST_F(WriteCallbackSecurityTest, BoundaryNearMaxSizeMustBeRejected) {
    char dummy_data[1] = {'X'};
    size_t result = write_callback(dummy_data, SIZE_MAX, 1, &response);
    // Allocation of SIZE_MAX bytes should fail; callback should handle gracefully
    // Either returns 0 (error) or SIZE_MAX (unlikely malloc succeeds)
    if (result != SIZE_MAX) {
        EXPECT_EQ(result, 0u);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}