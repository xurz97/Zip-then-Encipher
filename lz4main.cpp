#include "lz4.h"
#include <iostream>
#include <vector>

using namespace std;

vector<unsigned char> compressData(const vector<unsigned char>& input) {
    // 计算最大压缩后大小
    int maxCompressedSize = LZ4_compressBound(input.size());
    cout<<maxCompressedSize<<endl;
    // 分配内存用于压缩后的数据
    vector<unsigned char> compressedData(maxCompressedSize);

    // 压缩数据
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char*>(input.data()),
        reinterpret_cast<char*>(compressedData.data()),
        input.size(),
        maxCompressedSize);

    // 调整压缩数据的大小
    compressedData.resize(compressedSize);

    return compressedData;
}
vector<unsigned char> decompressData(const vector<unsigned char>& compressedData, int originalSize) {
    // 分配内存用于解压后的数据
    vector<unsigned char> decompressedData(originalSize);

    // 解压数据
    int decompressedSize = LZ4_decompress_safe(
        reinterpret_cast<const char*>(compressedData.data()),
        reinterpret_cast<char*>(decompressedData.data()),
        compressedData.size(),
        originalSize);

    // 检查解压后的数据大小
    if (decompressedSize < 0) {
        cerr << "Decompression failed" << endl;
        exit(1);
    }

    return decompressedData;
}
int main() {
    // 原始数据
    vector<unsigned char> originalData(1000) ;
    for(int i=0;i<originalData.size();i++) originalData[i]=i%256;
    
    // 压缩
    vector<unsigned char> compressedData = compressData(originalData);
    cout << "Compressed Size: " << compressedData.size() << endl;
    /*
    for(int i=0;i<compressedData.size();i++){
        cout<<static_cast<int>(compressedData[i])<<" ";
    }
    cout<<endl;
    */
    // 解压缩
    vector<unsigned char> decompressedData = decompressData(compressedData, originalData.size());
    cout << "Decompressed Size: " << decompressedData.size() << endl;
    /*
    for(int i=0;i<decompressedData.size();i++){
        cout<<static_cast<int>(decompressedData[i])<<" ";
    }
    cout<<endl;
    */
    return 0;
}