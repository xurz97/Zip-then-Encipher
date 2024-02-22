#include<stdio.h>
#include<stdlib.h>
 
#define NAME_LENGTH 100
#define BUFFER_SIZE 4096
#define MIN_SIZE 1
#define MAX_SIZE 1024
 
void FileSplit(FILE *file){
	if(file==NULL){
		printf("Unable to read file.\n");
		exit(-1);
	}
	char partname[NAME_LENGTH];
	int buffer[BUFFER_SIZE]; 
	int num=0;
	while(!feof(file)){
		sprintf(partname,"./part/part_%d",++num);
		FILE *fout=fopen(partname,"wb");
		if(file==NULL){
			printf("Unable to create file.\n");
			exit(-2);
		}
		int cnt=fread(buffer,1,4096,file);//read 1KB, may less than 1KB.
		fwrite(buffer,1,cnt,fout);
		fclose(fout);
	}
}
 
int main(){
	printf("Input Split filename \n>>");
	char filename[NAME_LENGTH];
	scanf("%s",filename);
	FILE *fin=fopen(filename,"rb");
	printf("Wait...\n");
	FileSplit(fin);
	fclose(fin);
	printf("Finish.\n");
	return 0;
}