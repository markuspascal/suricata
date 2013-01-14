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
    sigmatch_table[DETECT_SCANNING].name = "scanning";//der name fŸr das Modul der angegeben wird in der Rule
    sigmatch_table[DETECT_SCANNING].Match = DetectScanningMatch;
    sigmatch_table[DETECT_SCANNING].Setup = DetectScanningSetup;
    sigmatch_table[DETECT_SCANNING].Free = DetectScanningFree;
    sigmatch_table[DETECT_SCANNING].RegisterTests = DetectScanningRegisterTests;
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
    //fŸr jedes einzelne Paket aufegrufen
    int ret = 0;
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
    /* hier muss der host als key in einem Table abgelegt werden.
    	value ist der entsprechende Count wie oft ein Flag kam*/
   
    
   
    
   // printf("########### %d ###########\n",flags);
    //wenn noch nicht angelegt neu anlegen (in decode.h void pointer nimmt alles)
    ddata = (DetectScanningData *) h->scanning;
    if (!ddata) {
        /* initialize fresh Scanningdata */
       ddata = SCMalloc(sizeof(DetectScanningData));
       bzero(ddata, sizeof(DetectScanningData));
      
       h->scanning = ddata;
    }
    
    if(!ddata->data){
        printf("############## initialized table");
        ddata->data = table_create(50);     
    }
    
    TCPHdr* tcp_hdr = p->tcph;
    uint8_t flags = tcp_hdr->th_flags;
    static int b = 0;
    
    if(flags==16){  
        b+=1;
        //table_add(ddata->data,'asd',b);
       
    }
    
    //(ddata->cnt_packets)++;//heir werden die neuen Daten in den Ergebnispointer geschrieben
    //printf("host found, packets now %d\n", ddata->cnt_packets);
    //0 kein alert, 1 alert
    //ret = (ddata->cnt_packets > dsig->max_numpackets);
    ret = (b>4);
    HostRelease(h);
    return ret;
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
    dsig->max_numpackets = atoi(dummystr);

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
