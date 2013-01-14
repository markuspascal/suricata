#include <stdio.h>
#include <stdlib.h>

#ifndef _DETECT_SCANNING_H
#define	_DETECT_SCANNING_H

#define SCANNING_HASH_SIZE 32768

typedef struct DetectScanningSig_ {

    uint32_t max_allowed_distinct_dst_ips;

    uint32_t syn_number;
    uint32_t syn_time;//in seconds
    
    uint32_t ping_number;
    uint32_t ping_time;
    
    uint32_t fortlaufend;
} DetectScanningSig;

typedef struct DetectScanningData_ {
    Address src;
    
    HashTable * dstIP_count;

    uint16_t dst_port;

    uint32_t inc_ips;    //counter wieviele IPs in folge aufsteigend waren
    Address * lastDst;  //letzte ip DST Adresse zum vergleich mit der aktuellen
    uint32_t syn_counter; //counter wieviele SYNs an kamen
    //struct timeval syn_timer; //timestamp wann das erste SYN erhalten wurde TODO
    //struct timeval ping_timer; //timestamp wann der erste ping kam		TODO
    uint32_t ping_counter_diff_ips; //zaehlt die anzahl unterschiedlicher dst an den pings gehen
    
} DetectScanningData;

typedef struct DstIP_Count_ {
	uint32_t ip;
	uint32_t counter;
} DstIP_Count;

void DetectScanningRegister(void);


typedef struct syn_pair{
    int number;
    int time;
}SynPair;

char * toCharArray(char* sig){
  int k =0;
  while(sig[k]!='\0'){
      k++;
  }
  char string[k];
  memcpy(string,sig,k);
  return string;
}

SynPair parseForNumbersSyn(char* string, DetectScanningSig * sig){
    int index = 0;
    int pos = 0;
    int isTime = 0;
    int start;
    int end;
    SynPair pa;
    char *to;
    char toParse[];
    toParse = toCharArray(string);
    //printf("parsing for numbers\n");
    for(index;index<strlen(toParse);index++){
        if(toParse[index]==91){ // [
            start = index+1; 
            for(pos = index+1;pos<strlen(toParse);pos++){
                
                if(toParse[pos]==93){ // ]
                    end = pos;
                    index=pos+1;                    
                    
                    to = (char*) malloc((end-start));
                    strncpy(to, toParse+start, (end-start));
                    int a = atoi(to);
                    if(isTime==0){
                    	    sig->syn_number = a;
                    	    isTime=1;
                    }else{
                    	 sig->syn_time = a;    
                    }
                    printf("%d ",a);
                    
                }else if(toParse[pos]==91){
                    start = pos+1;
                }
            }
           
        }  
    }
    
    return pa;
    
}

SynPair parseForNumbersPing(char* String, DetectScanningSig * sig){
    int index = 0;
    int pos = 0;
    int isTime = 0;
    int start;
    int end;
    SynPair pa;
    char *to;
    char toParse[];
    toParse = toCharArray(string);
    //printf("parsing for numbers\n");
    for(index;index<strlen(toParse);index++){
        if(toParse[index]==91){ // [
            start = index+1; 
            for(pos = index+1;pos<strlen(toParse);pos++){
                
                if(toParse[pos]==93){ // ]
                    end = pos;
                    index=pos+1;                    
                    
                    to = (char*) malloc((end-start));
                    strncpy(to, toParse+start, (end-start));
                    int a = atoi(to);
                    if(isTime==0){
                    	    sig->ping_number = a;
                    	    isTime=1;
                    }else{
                    	 sig->ping_time = a;    
                    }
                    printf("%d ",a);
                    
                }else if(toParse[pos]==91){
                    start = pos+1;
                }
            }
           
        }  
    }
    
    return pa;
    
}


int parseForNumbersIP(char* string, DetectScanningSig * sig){
    int index = 0;
    int pos = 0;
    int isTime = 0;
    int start;
    int end;
   
    char *to;
    char toParse[];
    toParse = toCharArray(string);
    //printf("parsing for numbers\n");
    for(;index<strlen(toParse);index++){
        if(toParse[index]==91){ // [
            start = index+1; 
            for(pos = index+1;pos<strlen(toParse);pos++){
                
                if(toParse[pos]==93){ // ]
                    end = pos;
                    index=pos+1;                    
                    
                    to = (char*) malloc((end-start));
                    strncpy(to, toParse+start, (end-start));
                    int a = atoi(to);
                    if(isTime==0){
                    	    sig->fortlaufend = a;
                    	    isTime=1;
                    }
                    printf("%d ",a);
                    
                }else if(toParse[pos]==91){
                    start = pos+1;
                }
            }
           
        }  
    }
    
    return 1;
    
}



char** parseSig(char* string){
  char *p;
  char** signature_tokens;
  int index = 0;
  
  signature_tokens =(char**) malloc(4);
  p = strtok (string,"#");
  
  
  
  while (p != NULL)
  {
    
    signature_tokens[index] = p;
    index++;
    p = strtok (NULL, "#");
    
  }
  
  return signature_tokens;
}

#endif	/* _DETECT_SCANNING_H */
