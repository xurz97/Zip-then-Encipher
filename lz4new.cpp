#include "lz4.h"
#include <iostream>
using namespace std;
void compressData(const unsigned char* input, int inputLen, unsigned char* output, int& outputLen) {
    // 计算最大压缩后的大小
    int maxCompressedSize = LZ4_compressBound(inputLen);

    // 压缩数据
    outputLen = LZ4_compress_default(
        reinterpret_cast<const char*>(input),
        reinterpret_cast<char*>(output),
        inputLen,
        maxCompressedSize);

    if (outputLen < 0) {
        std::cerr << "Compression failed" << std::endl;
        exit(1);
    }
}
void decompressData(const unsigned char* input, int inputLen, unsigned char* output, int outputLen) {
    // 解压数据
    int decompressedSize = LZ4_decompress_safe(
        reinterpret_cast<const char*>(input),
        reinterpret_cast<char*>(output),
        inputLen,
        outputLen);

    if (decompressedSize < 0) {
        std::cerr << "Decompression failed" << std::endl;
        exit(1);
    }
}
int main() {
    // 原始数据
    unsigned char originalData[1000];
    int originalSize = sizeof(originalData) / sizeof(originalData[0]);
    for(int i=0;i<originalSize;i++) originalData[i]=i%256;
    // 创建压缩数据数组
    int maxCompressedSize = LZ4_compressBound(originalSize);
    unsigned char* compressedData = new unsigned char[maxCompressedSize];
    int compressedSize = 0;

    // 压缩数据
    compressData(originalData, originalSize, compressedData, compressedSize);
    std::cout << "Compressed Size: " << compressedSize << std::endl;
    /*for(int i=0;i<compressedSize;i++){
        cout<<static_cast<int>(compressedData[i])<<" ";
    }
    cout<<endl;
    */
    // 创建解压缩数据数组
    unsigned char* decompressedData = new unsigned char[originalSize];

    // 解压缩数据
    decompressData(compressedData, compressedSize, decompressedData, originalSize);
    std::cout << "Decompressed Size: " << originalSize << std::endl;
    /*for(int i=0;i<originalSize;i++){
        cout<<static_cast<int>(decompressedData[i])<<" ";
    }
    cout<<endl;
    */
    // 清理动态分配的内存
    delete[] compressedData;
    delete[] decompressedData;

    return 0;
}