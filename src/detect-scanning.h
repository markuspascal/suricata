#ifndef _DETECT_SCANNING_H
#define	_DETECT_SCANNING_H

#define SCANNING_HASH_SIZE 32768

typedef struct DetectScanningSig_ {
    uint32_t max_numpackets; /**< max number of allowed packets */
} DetectScanningSig;

typedef struct DetectScanningData_ {
    Address src;
    
    //HashTable * dstIP_count;
    //HashTable * ports_count;
    table_t * dstIp_count; //<dstip, count>
    table_t * dstPort_count; //<port, count>
    uint16_t incIps;    //counter wieviele IPs in folge aufsteigend waren
    Address * lastDst;  //letzte ip DST Adresse zum vergleich mit der aktuellen
    uint16_t syn_counter; //counter wieviele SYNs an kamen
    uint16_t syn_timer; //zum vergleich wieviel zeit vergangen ist. erhalt erstes syn, aberlauf des counter
    uint16_t ping_timer; //zum vergleich wieviel zeit vergangen ist. erhalt erstes ping, aberlauf des counter
    uint16_t ping_counter_diff_ips; //zaehlt die anzahl unterschiedlicher dst an den pings gehen
    
} DetectScanningData;

void DetectScanningRegister(void);

#endif	/* _DETECT_SCANNING_H */
