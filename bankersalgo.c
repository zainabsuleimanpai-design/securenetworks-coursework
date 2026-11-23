
/*
 * OSland - Deadlock Avoidance and Secure Resource Service
 * STUDENT QUESTION VERSION
 *
 * Total: 50 marks
 *
 * Complete TODO 1 to TODO 6.
 * The TLS networking framework is supplied.
 *
 * ================ BUILD & RUN ================
 *
 * 1) Compile (inside the coursework devcontainer, or on any
 *    machine with gcc and the OpenSSL development files):
 *
 *        gcc -std=c11 -Wall -Wextra bankersalgo.c \
 *            -o bankersalgo -lssl -lcrypto
 *
 *    If the compiler reports "openssl/ssl.h: No such file
 *    or directory", install OpenSSL first
 *    (Linux: sudo apt install libssl-dev).
 *
 *    The empty skeleton gives a few "unused parameter"
 *    warnings - expected; they disappear as you complete
 *    the TODOs.
 *
 * 2) Create a self-signed certificate for localhost. The
 *    client verifies the hostname, so keep "localhost" if
 *    server and client run on the same machine:
 *
 *        openssl req -x509 -newkey rsa:2048 \
 *            -keyout key.pem -out cert.pem -days 365 \
 *            -nodes -subj "/CN=localhost" \
 *            -addext "subjectAltName=DNS:localhost"
 *
 * 3) Local mode (no network, no certificate needed):
 *
 *        ./bankersalgo
 *
 * 4) TLS server (one terminal):
 *
 *        export OSLAND_TOKEN=osland-coursework-2026
 *        export OSLAND_CLIENT_ID=student01
 *        ./bankersalgo server 8443 cert.pem key.pem
 *
 * 5) TLS client (second terminal, SAME OSLAND_TOKEN):
 *
 *        export OSLAND_TOKEN=osland-coursework-2026
 *        ./bankersalgo client localhost 8443 cert.pem \
 *            student01 1 1 0 2
 *
 *    Client arguments:
 *        client <host> <port> <cert> <client-id> \
 *               <pid> <r0> <r1> <r2>
 *
 *    OSLAND_TOKEN must be at least 16 characters and
 *    identical on server and client. The client ID must
 *    match OSLAND_CLIENT_ID set on the server.
 *
 *    The server prints extra detail on its own console;
 *    the client only receives AUTH OK / DECISION lines.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define P 5
#define R 3
#define BUFFER 512

int available[R] = {3, 3, 2};

int total[R] = {10, 5, 7};

int allocation[P][R] = {
    {0, 1, 0},
    {2, 0, 0},
    {3, 0, 2},
    {2, 1, 1},
    {0, 0, 2}
};

int maximum[P][R] = {
    {7, 5, 3},
    {3, 2, 2},
    {9, 0, 2},
    {2, 2, 2},
    {4, 3, 3}
};

int need[P][R];

/* =================================================
   TODO 1: NEED MATRIX CALCULATION (6 MARKS)
   =================================================

   Calculate:
       Need = Maximum - Allocation

   Requirements:
   - Use nested loops.
   - Calculate for every process and resource.
   - Do not modify Maximum or Allocation.
*/

void calculateNeed(void)
{
    /* TODO 1: Write your code here */

    for (int z =0; z <P; z++)
        for (int h  = 0; h<R; h++)
            need[z][h] = maximum[z][h] - allocation[z][h];
}

/* =================================================
   TODO 2: SYSTEM STATE VALIDATION (6 MARKS)
   =================================================

   Check:
   1. Available resources are non-negative.
   2. Allocation does not exceed Maximum.
   3. Available + allocated = Total for each resource.

   Return 1 if valid, otherwise 0.
*/

int validateState(void)
{
    /* TODO 2: Write your code here */
    for (int h = 0; h < R; h++)
    {
        if (available [h] < 0)
            return 0;
        
        int allocated = 0;
        for (int z = 0; z < P; z++)
            allocated += allocation[z][h];
        
        if (available[h] + allocated != total[h])
            return 0;
    }
    
    
    for (int z = 0; z < P; z++)
        for (int h = 0; h < R; h++)
            if (allocation[z][h] < 0 || allocation[z][h] > maximum[z][h])
                return 0;
    return 1;
}

/* =================================================
   TODO 3: BANKER'S SAFETY ALGORITHM (12 MARKS)
   =================================================

   Implement:
   1. Work = Available.
   2. Finish[i] = false.
   3. Find an unfinished process with Need <= Work.
   4. Add its Allocation to Work.
   5. Mark the process finished.
   6. Store its PID in safeSequence.
   7. Repeat until all processes finish or no
      further process can execute.

   Return 1 for SAFE, 0 for UNSAFE.
*/

int safetyAlgorithm(int safeSequence[P])
{
    /* TODO 3: Write your code here */
    int work[R];
    bool finish[P];
    int count = 0;

    for (int h = 0; h < R; h++)
        work[h] = available[h];
    
    for (int z = 0; z < P; z++)
        finish[z] = false;
    
    while (count < P)
    {
        bool found = false;
        for (int z = 0; z < P; z++)
        {
            if (finish[z])
                continue;
            
            bool canRun = true;
            for (int h = 0; h < R; h++)
            {
                if (need[z][h] > work[h])
                {
                    canRun = false;
                    break;
                }
            }
            
            if (canRun)
            {
                for (int h = 0; h < R; h++)
                    work[h] += allocation[z][h];
                
                finish[z] = true;
                safeSequence[count++] = z;
                found = true;
            }
        }
        if (!found)
            return 0;
    }
    for (int z = 0; z < P; z++)
        if (!finish[z])
            return 0;
    
    return 1;
}

/* =================================================
   TODO 4: RESOURCE REQUEST ALGORITHM (12 MARKS)
   =================================================

   Requirements:
   1. Validate process ID.
   2. Check Request <= Need.
   3. Check Request <= Available.
   4. Temporarily allocate resources.
   5. Execute the safety algorithm.
   6. Grant request if safe.
   7. Roll back allocation if unsafe.
   8. Return 1 if granted, otherwise 0.
*/

int requestResources(int pid, int request[R])
{
    /* TODO 4: Write your code here */
    int sequence[P];

    calculateNeed();

    if (pid < 0 || pid >= P)
    {
        printf("\nInvalid process ID\n");
        return 0;
    }
    
    for (int h = 0; h < R; h++)
    {
        
        if (request[h] < 0)
        {
            printf("\nRequest values cannot be negative\n");
            return 0;
        }
        
        if (request[h] > need[pid][h])
        {
            printf("\nError: request exceeds the declared maximum need\n");
            return 0;
        }
        
        if (request[h] > available[h])
        {
            printf("\nResources not available - process must wait\n");
            return 0;
        }
    }
    
    /* pretend to allocate*/
    for (int h = 0; h< R; h++)
    {
        available[h] -= request[h];
        allocation[pid][h] += request[h];
        need[pid][h] -= request[h];
    }
    
    /* running the saftey alogrithm on the new state*/
    if (safetyAlgorithm(sequence))
    {
        /* safe: keep the allocation*/
        printf("\nSystem remains SAFE\n");
        printf("Safe Sequence: ");
        for (int z = 0; z < P; z++)
            printf("P%d ", sequence[z]);
        printf("\n\n");
        return 1;
    }
    
    
     /* undo step 4 */
    for (int h = 0; h < R; h++)
    {
        available[h] += request[h];
        allocation[pid][h] -= request[h];
        need[pid][h] += request[h];
    }
    printf("\nUnsafe state detected\n");
    printf("Allocation rolled back\n");
    
    return 0;
}

/* =================================================
   TODO 5: RESOURCE RELEASE (7 MARKS)
   =================================================

   Requirements:
   1. Validate process ID.
   2. Validate release quantities.
   3. Ensure Release <= Allocation.
   4. Update Allocation and Available.
   5. Return 1 if successful, otherwise 0.
*/

int releaseResources(int pid, int release[R])
{
    /* TODO 5: Write your code here */
    /* validate process ID */
    if (pid < 0 || pid >= P)
        return 0;
    for (int h = 0; h < R; h++)
        if (release[h] < 0 || release[h] > allocation[pid][h])
            return 0;

    /* giving the resources back */
    for  (int h = 0; h < R; h++)
    {
        allocation[pid][h] -= release[h];
        available[h] += release[h];
    }
    calculateNeed();
    

    return 1;
}

/* =================================================
   TODO 6: OS STATE REPORTING (7 MARKS)
   =================================================

   Display:
   - Process ID
   - Allocation matrix
   - Maximum matrix
   - Need matrix
   - Available resources

   Format the output as a readable table.
*/

void displayState(void)
{
    /* TODO 6: Write your code here */
    calculateNeed();

    printf("\n%-9s%-14s%-14s%s\n", "Process", "Allocation", "Maximum", "Need");
    for (int z = 0; z < P; z++)
    {
        printf("P%-8d", z);
        
        for (int h = 0; h < R; h++)
            printf("%d ", allocation[z][h]);
        printf("%8s", "");

        for (int h = 0; h < R; h++)
            printf("%d ", maximum[z][h]);
        printf("%8s", "");

        for (int h = 0; h < R; h++)
            printf("%d ", need[z][h]);
        printf("\n"); 
    }
    printf("\nAvailable Resources: "); 
    for (int h = 0; h < R; h++)
        printf("%d ", available[h]);

    printf("\nTotal Resources: "); 
    for (int h = 0; h < R; h++)
        printf("%d ", total[h]);

    printf("\n==========\n");
    
}

            


/* =================================================
   SUPPLIED OPERATING SYSTEM MENU
   ================================================= */

void localMenu(void)
{
    int choice, pid, values[R];
    int sequence[P];

    while (1)
    {
        printf("\n========== OSLAND ==========\n");
        printf("1. Display Resource State\n");
        printf("2. Run Safety Algorithm\n");
        printf("3. Request Resources\n");
        printf("4. Release Resources\n");
        printf("5. Validate State\n");
        printf("6. Exit\n");
        printf("Enter choice: ");

        if (scanf("%d", &choice) != 1)
            break;

        switch (choice)
        {
            case 1:
                displayState();
                break;

            case 2:
                calculateNeed();

                if (safetyAlgorithm(sequence))
                {
                    printf("SAFE STATE\n");
                    printf("Safe Sequence: ");

                    for (int i = 0; i < P; i++)
                        printf("P%d ", sequence[i]);

                    printf("\n");
                }
                else
                    printf("UNSAFE STATE\n");

                break;

            case 3:
                printf("Enter Process ID: ");
                if (scanf("%d", &pid) != 1)
                    return;

                printf("Enter request for %d resources: ", R);

                for (int i = 0; i < R; i++)
                    if (scanf("%d", &values[i]) != 1)
                        return;

                if (requestResources(pid, values))
                    printf("REQUEST GRANTED\n");
                else
                    printf("REQUEST DENIED\n");

                break;

            case 4:
                printf("Enter Process ID: ");
                if (scanf("%d", &pid) != 1)
                    return;

                printf("Enter release for %d resources: ", R);

                for (int i = 0; i < R; i++)
                    if (scanf("%d", &values[i]) != 1)
                        return;

                if (releaseResources(pid, values))
                    printf("RESOURCES RELEASED\n");
                else
                    printf("INVALID RELEASE\n");

                break;

            case 5:
                if (validateState())
                    printf("STATE VALID\n");
                else
                    printf("STATE INVALID\n");
                break;

            case 6:
                return;

            default:
                printf("Invalid choice\n");
        }
    }
}

/* =================================================
   SUPPLIED SECURE NETWORKING COMPONENT
   ================================================= */

static int validId(const char *id)
{
    size_t n = strlen(id);

    if (n == 0 || n > 64)
        return 0;

    for (size_t i = 0; i < n; i++)
    {
        char c = id[i];

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }

    return 1;
}

static int tlsReadLine(SSL *ssl, char *buf, size_t cap)
{
    size_t n = 0;

    while (n + 1 < cap)
    {
        char c;
        int k = SSL_read(ssl, &c, 1);

        if (k == 1)
        {
            if (c == '\n')
            {
                buf[n] = '\0';
                return 1;
            }

            if (c == '\0' || c == '\r')
                return 0;

            buf[n++] = c;
        }
        else
        {
            int e = SSL_get_error(ssl, k);

            if (e == SSL_ERROR_WANT_READ ||
                e == SSL_ERROR_WANT_WRITE)
                continue;

            return 0;
        }
    }

    return 0;
}

static int tlsWrite(SSL *ssl, const char *msg)
{
    size_t len = strlen(msg);
    size_t sent = 0;

    while (sent < len)
    {
        int k = SSL_write(ssl, msg + sent,
                          (int)(len - sent));

        if (k > 0)
            sent += (size_t)k;
        else
        {
            int e = SSL_get_error(ssl, k);

            if (e == SSL_ERROR_WANT_READ ||
                e == SSL_ERROR_WANT_WRITE)
                continue;

            return 0;
        }
    }

    return 1;
}

static int parseRequest(
    const char *line, int *pid, int req[R])
{
    char extra;

    return sscanf(line,
        "REQUEST %d %d %d %d %c",
        pid, &req[0], &req[1], &req[2],
        &extra) == 4;
}

static int createListener(const char *port)
{
    struct addrinfo hints, *list, *p;
    int fd = -1, yes = 1;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &list) != 0)
        return -1;

    for (p = list; p; p = p->ai_next)
    {
        fd = socket(p->ai_family,
                    p->ai_socktype,
                    p->ai_protocol);

        if (fd < 0)
            continue;

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   &yes, sizeof(yes));

        if (bind(fd, p->ai_addr,
                 p->ai_addrlen) == 0 &&
            listen(fd, 5) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(list);
    return fd;
}

static void serveClient(
    int fd, SSL_CTX *ctx,
    const char *token, const char *allowedId)
{
    SSL *ssl = SSL_new(ctx);

    char line[BUFFER], id[65], receivedToken[257];
    char response[BUFFER], extra;

    int pid, req[R];

    if (!ssl)
    {
        close(fd);
        return;
    }

    SSL_set_fd(ssl, fd);

    if (SSL_accept(ssl) != 1)
        goto cleanup;

    if (!tlsReadLine(ssl, line, sizeof(line)))
        goto cleanup;

    if (sscanf(line, "AUTH %64s %256s %c",
               id, receivedToken, &extra) != 2 ||
        !validId(id))
    {
        tlsWrite(ssl, "ERROR malformed authentication\n");
        goto cleanup;
    }

    if (strcmp(id, allowedId) != 0 ||
        strcmp(receivedToken, token) != 0)
    {
        tlsWrite(ssl, "ERROR authentication failed\n");
        goto cleanup;
    }

    if (!tlsWrite(ssl, "AUTH OK\n"))
        goto cleanup;

    if (!tlsReadLine(ssl, line, sizeof(line)))
        goto cleanup;

    if (!parseRequest(line, &pid, req))
    {
        tlsWrite(ssl, "ERROR malformed request\n");
        goto cleanup;
    }

    /* Authenticated requests only reach this point. */
    int granted = requestResources(pid, req);

    snprintf(response, sizeof(response),
        "DECISION %s; available=[%d,%d,%d]\n",
        granted ? "GRANTED" : "DENIED",
        available[0], available[1], available[2]);

    tlsWrite(ssl, response);

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
}

static int runServer(
    const char *port,
    const char *cert,
    const char *key)
{
    const char *token = getenv("OSLAND_TOKEN");
    const char *id = getenv("OSLAND_CLIENT_ID");

    if (!token || strlen(token) < 16 ||
        !id || !validId(id))
    {
        fprintf(stderr,
            "Set OSLAND_TOKEN (16+ characters) "
            "and OSLAND_CLIENT_ID.\n");
        return 1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx)
        return 1;

    SSL_CTX_set_min_proto_version(
        ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_chain_file(
            ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(
            ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int server = createListener(port);

    if (server < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("TLS server listening on %s\n", port);

    while (1)
    {
        int client = accept(server, NULL, NULL);

        if (client < 0)
        {
            if (errno == EINTR)
                continue;

            break;
        }

        serveClient(client, ctx, token, id);
    }

    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

static int runClient(
    const char *host, const char *port,
    const char *ca, const char *id,
    int pid, int req[R])
{
    const char *token = getenv("OSLAND_TOKEN");

    if (!token || strlen(token) < 16 ||
        !validId(id))
        return 1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx)
        return 1;

    SSL_CTX_set_min_proto_version(
        ctx, TLS1_2_VERSION);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(
            ctx, ca, NULL) != 1)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    struct addrinfo hints, *list, *p;
    int fd = -1, result = 1;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &list) != 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    for (p = list; p; p = p->ai_next)
    {
        fd = socket(p->ai_family,
                    p->ai_socktype,
                    p->ai_protocol);

        if (fd >= 0 &&
            connect(fd, p->ai_addr, p->ai_addrlen) == 0)
            break;

        if (fd >= 0)
            close(fd);

        fd = -1;
    }

    freeaddrinfo(list);

    if (fd < 0)
    {
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    char line[BUFFER], message[BUFFER];

    if (!ssl)
        goto cleanup;

    SSL_set_fd(ssl, fd);

    if (SSL_set1_host(ssl, host) != 1 ||
        SSL_connect(ssl) != 1)
        goto cleanup;

    snprintf(message, sizeof(message),
             "AUTH %s %s\n", id, token);

    if (!tlsWrite(ssl, message) ||
        !tlsReadLine(ssl, line, sizeof(line)))
        goto cleanup;

    puts(line);

    if (strcmp(line, "AUTH OK") != 0)
        goto cleanup;

    snprintf(message, sizeof(message),
             "REQUEST %d %d %d %d\n",
             pid, req[0], req[1], req[2]);

    if (!tlsWrite(ssl, message) ||
        !tlsReadLine(ssl, line, sizeof(line)))
        goto cleanup;

    puts(line);
    result = 0;

cleanup:
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(fd);
    SSL_CTX_free(ctx);

    return result;
}

/* =================================================
   MAIN FUNCTION
   ================================================= */

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);

    if (argc == 1)
    {
        localMenu();
        return 0;
    }

    if (argc == 5 &&
        strcmp(argv[1], "server") == 0)
        return runServer(argv[2], argv[3], argv[4]);

    if (argc == 10 &&
        strcmp(argv[1], "client") == 0)
    {
        int values[4];
        char *end;

        for (int i = 0; i < 4; i++)
        {
            errno = 0;
            long n = strtol(argv[i + 6], &end, 10);

            if (errno || end == argv[i + 6] ||
                *end || n < 0 || n > INT_MAX)
            {
                fprintf(stderr, "Invalid numeric input\n");
                return 1;
            }

            values[i] = (int)n;
        }

        int req[R] = {
            values[1], values[2], values[3]
        };

        return runClient(
            argv[2], argv[3], argv[4], argv[5],
            values[0], req);
    }

    fprintf(stderr, "Invalid arguments\n");
    return 1;
}
