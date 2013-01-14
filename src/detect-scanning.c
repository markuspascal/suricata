/**
 * \file
 *
 * \author Turk & J.D.
 *
 * Implements the Scanning keyword
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-scanning.h" 
#include "util-debug.h"

#include "host.h"
#include "libhtp/htp/dslib.h"

/*prototypes*/
int DetectScanningMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectScanningSetup (DetectEngineCtx *, Signature *, char *);
void DetectScanningFree (void *);
void DetectScanningRegisterTests (void);

void DetectScanningRegister(void) {
    printf("################ REGISTER ##################");
    sigmatch_table[DETECT_SCANNING].name = "scanning";//der name f�r das Modul der angegeben wird in der Rule
    sigmatch_table[DETECT_SCANNING].Match = DetectScanningMatch;
    sigmatch_table[DETECT_SCANNING].Setup = DetectScanningSetup;
    sigmatch_table[DETECT_SCANNING].Free = DetectScanningFree;
    sigmatch_table[DETECT_SCANNING].RegisterTests = DetectScanningRegisterTests;
}

uint32_t ip_hash_fkt(HashTable *ht, void *data, uint16_t datalen) {

  return ((DstIP_Count *) data)->ip;
}

char ip_compare_fkt(void *data1, uint16_t len1, void *data2, uint16_t len2) {
  	return ((DstIP_Count *) data1)->ip > ((DstIP_Count *) data2)->ip;
}

void HTFree(void *ht) {
    uint32_t i = 0;
 
    if (ht == NULL)
  	  return;
 
    /* free the buckets */
    for (i = 0; i < ((HashTable*)ht)->array_size; i++) {
	HashTableBucket *hashbucket = ((HashTable*) ht)->array[i];
  	while (hashbucket != NULL) {
  		HashTableBucket *next_hashbucket = hashbucket->next;
  		if (((HashTable*)ht)->Free != NULL)
  			((HashTable*)ht)->Free(hashbucket->data);
		SCFree(hashbucket);
		hashbucket = next_hashbucket;
	}
    }
 
    /* free the arrray */
    if (((HashTable*)ht)->array != NULL)
	SCFree(((HashTable*)ht)->array);
 
    SCFree(ht);
}

/**
 * \brief This function is used to match packets via the Scanning rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectScanningData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectScanningMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {

    DetectScanningSig *dsig = (DetectScanningSig *) m->ctx;
    DetectScanningData *ddata;
    Host *h;

    if (PKT_IS_PSEUDOPKT(p)
        || !PKT_IS_IPV4(p)
        || p->flags & PKT_HOST_SRC_LOOKED_UP
        || p->payload_len == 0) {
        return 0;
    }

    /* TODO: Inspect the packet contents here.
     * Suricata defines a `Packet` structure in decode.h which already defines 
     * many useful elements -- have a look! */

    h = HostGetHostFromHash(&(p->src));
    p->flags |= PKT_HOST_SRC_LOOKED_UP;
    
    if (h == NULL) {
        printf("host not found!\n");
        return 0;
    }
     
   
    
   // printf("########### %d ###########\n",flags);
    //wenn noch nicht angelegt neu anlegen (in decode.h void pointer nimmt alles)
    ddata = (DetectScanningData *) h->scanning;
    if (!ddata) {
        /* initialize fresh Scanningdata */
        ddata = (DetectScanningData*) SCMalloc(sizeof(DetectScanningData));
        bzero(ddata, sizeof(DetectScanningData));
      
        h->scanning = ddata;

	ddata->dstIP_count = HashTableInit(12480, ip_hash_fkt, ip_compare_fkt, HTFree);
	
    }
    
    
    TCPHdr* tcp_hdr = p->tcph;
    uint8_t flags = tcp_hdr->th_flags;
    
    uint32_t dst_ip = p->dst.address.address_un_data32[0]; //act.dst-ip of paket
    uint32_t last_dst_ip = ddata->lastDst->address.address_un_data32[0]; //last dst-ip
    
    uint8_t last_ip_field = last_dst_ip & 0xff;
    uint8_t act_last_ip_field = p->dst.address.address_un_data32[0] & 0xff;
    
    //syn flag
    if (flags == 16) {

	uint32_t num_distinct_dst_ips = 0;
        DstIP_Count * pair = (DstIP_Count *) SCMalloc(sizeof(DstIP_Count));
	memset(pair, 0, sizeof(DstIP_Count));

	pair->ip = dst_ip;
	pair->counter++;

	DstIP_Count * ht_pair = (DstIP_Count *) HashTableLookup(ddata->dstIP_count, pair, sizeof(DstIP_Count));

	if (ht_pair) {
		ht_pair->counter++;
		SCFree(pair);

		if (ht_pair->counter >= 4) {
			num_distinct_dst_ips = HashTableRemove(ddata->dstIP_count, ht_pair, sizeof(DstIP_Count));
		}
	} else {
		num_distinct_dst_ips = HashTableAdd(ddata->dstIP_count, pair, sizeof(DstIP_Count));
	}
	ddata->syn_counter++;
	
	//Alert Rule: 1 IP has tried to connect to too many hosts
	if (num_distinct_dst_ips >= dsig->max_allowed_distinct_dst_ips) {
		HashTableFree(ddata->dstIP_count);
		return 1;
	}

	//Alert Rule: 1 IP sends more then allowed SYN
	if (ddata->syn_counter >= dsig->syn_number) {
		ddata->syn_counter = 0;
		return 1;
	}

	if (last_ip_field < act_last_ip_field) {
		ddata->inc_ips++;
	}
	else
	{
		ddata->inc_ips = 0;
	}

	//Alert Rule: 1 IP sends SYN to incremented IPs (last field)
	if (ddata->inc_ips >= dsig->fortlaufend) {
		ddata->inc_ips = 0;
		return 1;
	}

    } else if ((ICMPV4_GET_TYPE(p) == ICMP_ECHO) && (dst_ip != last_dst_ip)) {
	
	ddata->ping_counter_diff_ips++;
	//Alert Rule: 1 IP sends more then allowed ICMP Echo Requests (Ping)
	if (ddata->ping_counter_diff_ips >= dsig->ping_number) {
		ddata->ping_counter_diff_ips = 0;
		return 1;
	}
    }
    
    //(ddata->cnt_packets)++;//heir werden die neuen Daten in den Ergebnispointer geschrieben
    //printf("host found, packets now %d\n", ddata->cnt_packets);
    //0 kein alert, 1 alert
    //ret = (ddata->cnt_packets > dsig->max_numpackets);

    HostRelease(h);
    return 0;
}

/**
 * \brief this function is used to setup the dummy environment
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param dummystr pointer to the user provided dummy options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectScanningSetup (DetectEngineCtx *de_ctx, Signature *s, char *dummystr) {
    printf("############## SETUP ##############");
    /*wird nur einmal aufgerufen am anfang*/	
    SigMatch *sm = NULL;
    DetectScanningSig *dsig = NULL;
    
    dsig = SCMalloc(sizeof(DetectScanningSig));
    if (dsig == NULL) { goto error; }

    sm = SigMatchAlloc();
    if (sm == NULL) { goto error; }
    
    /*hier musss der dummystr verarbeitet werden 
    und die entsprechenden Felder in der ScanningDataSig gesetzt werden
    ...definiert worauf geachtet wird*/
    char **signature_tokens = parseSig(dummystr);
    parseForNumbersSyn(signature_tokens[0],dsig);
    parseForNumbersPing(signature_tokens[1],dsig);
    parseForNumbersIP(signature_tokens[2],dsig);
    
    //dsig->max_numpackets = atoi(dummystr);

    sm->type = DETECT_SCANNING;
    sm->ctx = (void *) dsig;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (dsig != NULL) SCFree(dsig);
    if (sm != NULL) SCFree(sm);
    return -1;
}

void DetectScanningFree (void *ptr) {
    DetectScanningData *ed = (DetectScanningData*) ptr;
    SCFree(ed);
}

void DetectScanningRegisterTests(void) {
    #ifdef UNITTESTS
    // TODO
    #endif
}
