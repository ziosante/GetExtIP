#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <intuition/intuition.h>
#include <libraries/gadtools.h>
#define BUFFER_SIZE 4096
#define BUFFER_SIZE_HEADER 1024
#define MAX_ERROR_MSG 0x1000
#ifndef SHUT_RD 

enum {
    SHUT_RD = 0, /* No more receptions.  */
#define SHUT_RD         SHUT_RD
    SHUT_WR, /* No more transmissions.  */
#define SHUT_WR         SHUT_WR
    SHUT_RDWR /* No more receptions or transmissions.  */
#define SHUT_RDWR       SHUT_RDWR
};
#endif

#ifdef __M68K__
size_t __stack = 8192;
#endif

struct Window *myWindow;
struct Gadget *glist = NULL;
struct Screen *pubScreen;
APTR visual;

void exitclose(int ret) {
    if (myWindow) CloseWindow(myWindow);
    if (glist) FreeGadgets(glist);
    if (visual) FreeVisualInfo(visual);
    if (pubScreen) UnlockPubScreen(NULL, pubScreen);
    exit(ret);
}

int socket_connect(char *host, int port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    if ((hp = gethostbyname(host)) == NULL) {
        printf("gethostbyname error\n");
        exitclose(5);
    }
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof (int));

    if (sock == -1) {
        printf("setsockopt error\n");
        exitclose(5);
    }

    if (connect(sock, (struct sockaddr *) &addr, sizeof (struct sockaddr_in)) == -1) {
        printf("connect error\n");
        exitclose(5);

    }
    return sock;
}

int match(char text[], char pattern[]) {
    int c, d, e, text_length, pattern_length, position = -1;

    text_length = strlen(text);
    pattern_length = strlen(pattern);

    if (pattern_length > text_length) {
        return (-1);
    }

    for (c = 0; c <= text_length - pattern_length; c++) {
        position = e = c;

        for (d = 0; d < pattern_length; d++) {
            if (pattern[d] == text[e]) {
                e++;
            } else {
                break;
            }
        }
        if (d == pattern_length) {
            return (position);
        }
    }

    return (-1);
}

void substring(char s[], char sub[], int p, int l) {
    int c = 0;

    while (c < l) {
        sub[c] = s[p + c - 1];
        c++;
    }
    sub[c] = '\0';
}

void getip(char *IP) {
    int fd, start, finish;
    char buffer[BUFFER_SIZE];
    char header[BUFFER_SIZE_HEADER];
    char *host = "checkip.dyndns.org";
    char *pattern = "<body>Current IP Address: ";

    fd = socket_connect(host, 80);
    bzero(header, BUFFER_SIZE_HEADER);
    strcat(header, "GET / HTTP/1.0\r\nHost:");
    strcat(header, host);
    strcat(header, "\r\n\r\n\r\n");
    write(fd, header, strlen(header));
    bzero(buffer, BUFFER_SIZE);

    read(fd, buffer, BUFFER_SIZE - 1); // read 1024 bytes, should be enough since the response from checkip.dyndns.org is about 300 bytes
    shutdown(fd, SHUT_RDWR);
    close(fd);

    start = (match(buffer, pattern)) + strlen(pattern);
    finish = match(buffer, "</body>");
    substring(buffer, IP, start + 1, (finish - start));
}

int main(void) {
    /* Type of gadgets to display */
    ULONG Gadgetkinds[1] = {BUTTON_KIND};
    struct TextAttr topaz8 = {(STRPTR) "topaz.font", 8, 0, 1};
    /* Data for gadget structures */
    struct NewGadget Gadgetdata[1] = {
        109, 62, 60, 28, (UBYTE *) "UPDATE", &topaz8, 1, PLACETEXT_IN, NULL, NULL
    };
    /* Extra information for gadgets using Tags */
    ULONG GadgetTags[] = {
        (GTST_MaxChars), 256, (TAG_DONE),
        (GTNM_Border), TRUE, (TAG_DONE),
        (TAG_DONE)
    };
    short int gui = 0;
    struct RDArgs *rd;
    char template[50];
    LONG params[1];
    int closewin = FALSE; /* Flag used to end program */
    struct IntuiMessage *msg; /* Structure to store Intuition message data */
    ULONG msgClass;
    char *ver1 = "GetExtIP 1.3";
    UBYTE result[255];
    struct IntuiText WinText = {1, 0, JAM2, 0, 0, NULL, &result[0], NULL};
    char myIP[16];
    struct Gadget * myGadgets[1], *gad1, *gadAddr;
    UWORD gadgetid;

    strcpy(template, "GUI/S");
    params[0] = 0;
    rd = ReadArgs(template, params, NULL);
    if (rd) {
        if ((params[0])) gui = 1;
        FreeArgs(rd);
    } else {
        printf("$VER: GetExtIP 1.3 (12-Sep-2018) by Sante Nocciolino\nError processing options!\n");
        return(5);
    }

    getip(myIP);
    /* open gui */
    if (gui == 1) {
        /* Lock screen and get visual info for gadtools */
        if (pubScreen = LockPubScreen(NULL)) {
            if (!(visual = GetVisualInfo(pubScreen, TAG_DONE))) {
                printf("Failed to get visual info.\n");
                return (5);
            }
        } else {
            printf("Failed to lock screen.\n");
            return (5);
        }

        /* Create the gadget list */
        if (!(gad1 = CreateContext(&glist))) {
            printf("Failed to create gadtools context.\n");
            return (5);
        }
        /* Create gadgets specify gadget kind, a Gadget, NewGadget data and extra tag info */
        Gadgetdata[0].ng_VisualInfo = visual;
        if (myGadgets[0] = gad1 = CreateGadgetA(Gadgetkinds[0], gad1, &Gadgetdata[0], (struct TagItem *) &GadgetTags[0])) {
        } else {
            printf("Failed to create gadget\n");
        }


        myWindow = OpenWindowTags(NULL,
                WA_Left, 20, WA_Top, 20,
                WA_Width, 280, WA_Height, 96,
                WA_IDCMP, IDCMP_CLOSEWINDOW | IDCMP_GADGETUP,
                WA_Flags, WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_CLOSEGADGET | WFLG_ACTIVATE | WFLG_SMART_REFRESH,
                WA_Gadgets, glist,
                WA_Title, ver1,
                WA_PubScreenName, "Workbench",
                TAG_DONE);

        GT_RefreshWindow(myWindow, NULL); /* Update window */
        
        sprintf(result, "Your external IP:");
        PrintIText(myWindow->RPort, &WinText, 6, 32);
        sprintf(result, myIP);
        PrintIText(myWindow->RPort, &WinText, 6, 44);

        while (closewin == FALSE) { /* Run program until window is closed */
            Wait(1L << myWindow->UserPort->mp_SigBit); /* Wait for an event! */
            msg = GT_GetIMsg(myWindow->UserPort); /* Get message data    */
            msgClass = msg->Class; /* What has been clicked? */
            GT_ReplyIMsg(msg); /* Close message */
            if (msgClass == IDCMP_CLOSEWINDOW) { /* Check here if Close    Window selected */
                closewin = TRUE;
            }
            if (msgClass == IDCMP_GADGETUP) {
                gadAddr = (struct Gadget *) msg->IAddress;
                gadgetid = gadAddr->GadgetID;
                if (gadgetid == 1) { /* Test if Button pressed */
                    sprintf(result, "Updating...                   ");
                    PrintIText(myWindow->RPort, &WinText, 6, 44);
                    Delay(200);
                    getip(myIP);
                    sprintf(result, "                              ");
                    PrintIText(myWindow->RPort, &WinText, 6, 44);
                    sprintf(result, myIP);
                    PrintIText(myWindow->RPort, &WinText, 6, 44);
                }
            }
        }
        if (myWindow) CloseWindow(myWindow);
        if (glist) FreeGadgets(glist);
        if (visual) FreeVisualInfo(visual);
        if (pubScreen) UnlockPubScreen(NULL, pubScreen);
    } else {
        printf("%s\n", myIP);
    }
    return (0);
}

