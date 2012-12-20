#ifndef _DETECT_SCANNING_H
#define	_DETECT_SCANNING_H

#define SCANNING_HASH_SIZE 32768

typedef struct DetectScanningSig_ {
    uint32_t max_numpackets; /**< max number of allowed packets */
} DetectScanningSig;

typedef struct DetectScanningData_ {
    uint32_t cnt_packets;   /** < number of packets sent */
} DetectScanningData;

void DetectScanningRegister(void);

#endif	/* _DETECT_SCANNING_H */
