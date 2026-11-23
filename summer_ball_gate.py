"""
summer_ball_gate_TODO.py - Secure e-ticket system for the Students' Union Summer Ball

    Gate 1  forged tickets    ->  Ed25519 digital signatures
    Gate 2  copied QR codes   ->  time-based one-time codes (TOTP, RFC 6238), TLS, QR images
    Gate 3  repeated entry    ->  per-gate entry lists, synchronised through a hub with HMAC

Requirements:   pip install cryptography "qrcode[pil]" opencv-python

Configuration:  STUDENT_ID (below) sets the event name, code interval, code length and ports
Usage:          python summer_ball_gate_TODO.py 1      Part 1      (TODO 1.1 - 1.3)
                python summer_ball_gate_TODO.py 2      Parts 1-2   (TODO 2.1 - 2.6)
                python summer_ball_gate_TODO.py        Parts 1-3   (TODO 3.1 - 3.4)

Lines marked  ...  # TODO are to be completed. Each TODO is divided into numbered steps,
and the comment beside each  ...  describes the expected code. All other code is provided.
For a failing test, the output identifies the incomplete function and the line numbers.
"""
import base64, datetime, hashlib, hmac, inspect, io, json, re, secrets, socket, ssl, struct, sys, \
    textwrap, threading, time, tokenize
from contextlib import contextmanager

import cv2
import qrcode
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

STUDENT_ID = "00000000"                    # student ID; determines the configuration below

# Configuration derived from STUDENT_ID
PERSONAL = hashlib.sha256(STUDENT_ID.strip().encode()).digest()
FINGERPRINT = PERSONAL.hex()[:8]
EVENT = "su-ball-2027-" + PERSONAL.hex()[:4]
STEP = 10 + PERSONAL[0] % 21               # the code in the QR changes every 10-30 seconds
DIGITS = 6 + PERSONAL[1] % 3               # the code has 6-8 digits
BOX_OFFICE = ("127.0.0.1", 7000 + PERSONAL[2] % 1000)   # TLS server
HUB = ("127.0.0.1", 9000 + PERSONAL[3] % 1000)          # plain TCP server, every message carries an HMAC

SIGNING_KEY = ed25519.Ed25519PrivateKey.generate()    # private key: box office only
PUBLIC_KEY = SIGNING_KEY.public_key()                 # public key: every scanner
GATE_KEY = secrets.token_bytes(32)                    # shared secret: box office, scanners, hub


# =============================================================================
# HELPERS
# =============================================================================
def to_bytes(data):                        # the same dict always gives the same bytes
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def b64(raw):                              # bytes -> text
    return base64.urlsafe_b64encode(raw).decode()


def unb64(text):                           # text -> bytes
    return base64.urlsafe_b64decode(text)


def send(sock, message):                   # 4-byte length + JSON
    data = json.dumps(message).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def receive(sock):
    stream = sock.makefile("rb")
    header = stream.read(4)
    if len(header) < 4:
        raise ConnectionError("no reply from the server (the server reported an error)")
    size = struct.unpack(">I", header)[0]
    return json.loads(stream.read(size))


# =============================================================================
# PART 1 - GATE 1: FORGED TICKETS (digital signatures)
# =============================================================================
def make_ticket(ticket_id, name, key=SIGNING_KEY):
    """TODO 1.1  Create a signed ticket: base64(details) + "." + base64(signature)."""
    details = {"id": ticket_id, "name": name, "event": EVENT}       # TODO 1.1: a dict with "id", "name" and "event" (EVENT)
    # Step 1: turn the details into bytes
    data = to_bytes(details)                # TODO 1.1: use the helper to_bytes()
    # Step 2: sign the bytes with the private key
    signature = key.sign(data)         # TODO 1.1: an Ed25519 key has a .sign(bytes) method
    # Step 3: join both parts into one line of text
    ticket = b64(data) + "." + b64(signature)                     # TODO 1.1: b64() of each part, with "." between them
    print(f"   [BOX OFFICE] details   : {data.decode()}")
    print(f"   [BOX OFFICE] signature : {signature.hex()[:32]}...  ({len(signature)} bytes)")
    return ticket


def check_ticket(ticket):
    """TODO 1.2  Return the ticket details if the signature is valid, otherwise None.
    Only the public key is used, so verification works offline."""
    try:
        # Step 1: split the ticket at "." and turn both parts back into bytes
        data_text, signature_text = ticket.split(".")     # TODO 1.2: split the text at "."
        data, signature = unb64(data_text), unb64(signature_text)             # TODO 1.2: unb64() of each part
        # Step 2: check the signature with the public key (raises InvalidSignature if invalid)
        PUBLIC_KEY.verify(signature, data)        # TODO 1.2: PUBLIC_KEY has a .verify(signature, data) method
    except (ValueError, InvalidSignature):
        print("   [SCANNER]    signature verification failed - ticket rejected")
        return None
    # Step 3: the signature is valid, so the details can be trusted
    details = json.loads(data)                       # TODO 1.2: json.loads() turns the bytes back into a dict
    # Step 4: reject a valid ticket issued for a different event
    if details["event"] != EVENT:    # TODO 1.2: if details["event"] is not EVENT:
        print("   [SCANNER]    ticket is for a different event - ticket rejected")
        return None    #           print a message and return None
    print(f"   [SCANNER]    signature verified: {details}")
    return details


def edit_name(ticket, new_name):
    """TODO 1.3  Simulate tampering: change the holder name in a valid ticket, keeping its original signature."""
    # Step 1: split the ticket and decode the details into a dict
    data_text, signature_text = ticket.split(".")     # TODO 1.3: split at "." (like in check_ticket)
    details = json.loads(unb64(data_text))     # TODO 1.3: json.loads() of unb64(data_text)
    # Step 2: change the holder name
    details["name"] = new_name     # TODO 1.3: put new_name in the details
    # Step 3: combine the modified details with the original signature
    edited = b64(to_bytes(details)) + "." + signature_text   # TODO 1.3: details encoded as in make_ticket, then "." and signature_text
    print(f"   [TAMPER]     holder name changed to {new_name}; original signature kept")
    return edited


# =============================================================================
# PART 2 - GATE 2: COPIED QR CODES (TOTP, QR images, TLS)
# =============================================================================
def totp(secret, t, step=STEP, digits=DIGITS):
    """TODO 2.1  RFC 6238: the code for time t. It changes every `step` seconds."""
    # Step 1: the number of the time slot, packed as 8 bytes (big-endian)
    counter = ...                       # TODO 2.1: struct.pack(">Q", ...) of the slot number int(t // step)
    # Step 2: HMAC-SHA1 of the counter, with the secret as the key
    mac = ...                           # TODO 2.1: hmac.new(key, data, hashlib.sha1).digest()
    # Step 3: "dynamic truncation" (RFC 4226): the last byte gives where to take 4 bytes from
    i = ...                             # TODO 2.1: the last byte of mac, AND 0x0F
    number = ...                        # TODO 2.1: int.from_bytes() of the 4 bytes from i ("big"), AND 0x7FFFFFFF
    # Step 4: keep the last `digits` digits, with leading zeros
    return ...                          # TODO 2.1: number % 10 ** digits, as text; .zfill(digits) adds the zeros


def ticket_secret(ticket_id):              # each ticket has its own TOTP secret
    return hmac.new(GATE_KEY, ticket_id.encode(), hashlib.sha256).digest()


def save_qr(text, filename):
    """TODO 2.2  Save the text as a QR image."""
    ...                                 # TODO 2.2: qrcode.make(text) gives an image with a .save(filename) method
    print(f"   [WALLET]     QR image saved as {filename}")


def read_qr(filename):
    """TODO 2.2  Read the text from a QR image."""
    text, _, _ = ...                    # TODO 2.2: cv2.QRCodeDetectorAruco().detectAndDecode() of cv2.imread(filename)
    print(f"   [SCANNER]    {filename} read: {len(text)} characters")
    return text


def server_tls_context():
    """TODO 2.3  Server TLS context for the box office: load its certificate and private key."""
    context = ...                       # TODO 2.3: ssl.SSLContext() for a server
    ...                                 # TODO 2.3: reject versions older than TLS 1.2 (.minimum_version)
    ...                                 # TODO 2.3: load box.crt and box.key with .load_cert_chain()
    return context


def client_tls_context():
    """TODO 2.3  Client TLS context for the wallet: trust only the box office certificate."""
    context = ...                       # TODO 2.3: ssl.SSLContext() for a client
    ...                                 # TODO 2.3: reject versions older than TLS 1.2 (.minimum_version)
    ...                                 # TODO 2.3: trust only box.crt, with .load_verify_locations()
    return context


def make_certificate():                    # self-signed certificate for "boxoffice"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "boxoffice")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("boxoffice")]), critical=False)
            .sign(key, hashes.SHA256()))
    with open("box.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open("box.key", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


def start_server(address, handler, tls=False):    # runs handler(request) for each connection
    server = socket.create_server(address)
    context = server_tls_context() if tls else None

    def loop():
        while True:
            conn, _ = server.accept()
            try:
                if context:
                    conn = context.wrap_socket(conn, server_side=True)
                send(conn, handler(receive(conn)))
            except Exception as e:                 # a faulty request must not stop the server
                print(f"   [SERVER]     error in {handler.__name__}(): {type(e).__name__}: {e}")
            finally:
                conn.close()

    threading.Thread(target=loop, daemon=True).start()


def ask(address, message, tls=False):      # connect, send one message, return the reply
    sock = socket.create_connection(address)
    if tls:
        sock = client_tls_context().wrap_socket(sock, server_hostname="boxoffice")
        print(f"   [WALLET]     TLS connection established ({sock.version()}); box office certificate verified")
    with sock:
        send(sock, message)
        return receive(sock)


# ----------------------------------------------------------------- BOX OFFICE
orders = {}          # SHA-256 of an order code -> ticket id  (the code itself is never stored)
names = {}           # ticket id -> holder's name
used_codes = set()   # SHA-256 of the order codes already used


def sell(name):
    ticket_id = f"T-{len(names) + 1:04d}"
    order_code = secrets.token_hex(4)
    orders[hashlib.sha256(order_code.encode()).hexdigest()] = ticket_id
    names[ticket_id] = name
    print(f"   [BOX OFFICE] {ticket_id} issued to {name}; one-time order code {order_code}")
    return order_code


def box_office(request):
    """TODO 2.4  Handle a request {"order_code": ...}. Each order code can be used only once."""
    print(f"   [BOX OFFICE] ticket requested with order code {request['order_code']}")
    code_hash = ...                     # TODO 2.4: SHA-256 of the order code as hex text (as in sell())
    # Step 1: reject an order code that has already been used
    ...                                 # TODO 2.4: if code_hash is in used_codes: print a message
                                        #           and return {"error": "order code already used"}
    # Step 2: reject an unknown order code
    ...                                 # TODO 2.4: if code_hash is not in orders: print a message
                                        #           and return {"error": "unknown order code"}
    # Step 3: mark the code as used, then return the signed ticket and its secret
    ...                                 # TODO 2.4: add code_hash to used_codes so that it cannot be reused
    ticket_id = ...                     # TODO 2.4: look the ticket id up in orders
    print(f"   [BOX OFFICE] order code accepted - sending {ticket_id}; code marked as used")
    return ...                          # TODO 2.4: {"ticket": make_ticket(...) for the holder in names,
                                        #            "secret": ticket_secret(ticket_id) as text with b64()}


# ----------------------------------------------------------------- WALLET (mobile device)
class Wallet:
    def __init__(self, owner):
        self.owner = owner

    def download(self, order_code):
        """TODO 2.5  Download the ticket from the box office over TLS using a one-time order code."""
        print(f"   [WALLET]     {self.owner}: requesting ticket from the box office over TLS")
        # Step 1: send the order code to the box office over TLS
        reply = ...                         # TODO 2.5: ask() the BOX_OFFICE {"order_code": order_code}, with tls=True
        # Step 2: if the box office rejected the request, return the reason
        ...                                 # TODO 2.5: if "error" is in reply, return "REFUSED - " + the error
        # Step 3: store the ticket, and the secret as bytes
        self.ticket, self.secret = ...      # TODO 2.5: reply["ticket"], and unb64() of reply["secret"]
        return "Ticket downloaded"

    def show(self, filename, t=None):
        """TODO 2.5  Create the QR image: ticket + "." + the code for time t."""
        t = time.time() if t is None else t
        # Step 1: the code for time t
        code = ...                          # TODO 2.5: totp() of self.secret for time t
        print(f"   [WALLET]     code at {time.strftime('%H:%M:%S', time.localtime(t))} is {code}")
        # Step 2: save the QR image
        ...                                 # TODO 2.5: save_qr() of self.ticket + "." + code, as filename


# =============================================================================
# PART 3 - GATE 3: REPEATED ENTRY (entry lists, hub, HMAC)
# =============================================================================
hub_list = {}        # ticket id -> set of gates that admitted it
alerts = []          # tickets for which the hub raised a DUPLICATE ENTRY alert


def make_mac(message):
    """TODO 3.2  HMAC-SHA256 of a message (a dict) using the shared GATE_KEY, as hex text."""
    return ...                          # TODO 3.2: hmac.new(GATE_KEY, to_bytes(message), ...).hexdigest()


def hub(request):
    """TODO 3.3  Handle a gate message {"gate": n, "entries": [ticket ids], "mac": ...}."""
    # Step 1: remove the HMAC from the message and verify it
    mac = ...                           # TODO 3.3: remove "mac" from the message with request.pop("mac", "")
    ...                                 # TODO 3.3: if mac does not match make_mac(request) (hmac.compare_digest):
                                        #           print a message and return {"error": "REJECTED - bad HMAC"}
    print(f"   [HUB]        HMAC verified: gate {request['gate']} reports {request['entries']}")
    # Step 2: record which gates admitted each ticket; two gates indicate a duplicate entry
    for ticket_id in request["entries"]:
        ...                             # TODO 3.3: gates = hub_list.setdefault(ticket_id, set());
                                        #           if request["gate"] is not in gates, add it, and if gates
                                        #           now has 2 entries: alerts.append(ticket_id) and print
                                        #           "*** DUPLICATE ENTRY ... ***"
    # Step 3: reply with the full list: ticket id -> first gate of entry
    return ...                          # TODO 3.3: {"all": {each ticket id in hub_list: the min() of its gates}}


class Scanner:
    def __init__(self, gate):
        self.gate = gate
        self.seen = {}                     # ticket id -> gate of entry
        self.online = True                 # False = network unavailable

    def code_is_fresh(self, ticket_id, code, t):
        """TODO 2.6  Return True if the code matches the current or the previous time slot."""
        # Step 1: the ticket secret, and the expected codes for the current and previous time slots
        secret = ...                        # TODO 2.6: ticket_secret() of the ticket id
        now, before = ...                   # TODO 2.6: totp() of the secret for time t, and for time t - STEP
        print(f"   [SCANNER {self.gate}]  QR code value {code}; expected {now} (or previous {before})")
        # Step 2: compare in constant time with hmac.compare_digest
        return ...                          # TODO 2.6: True if code matches now or before (hmac.compare_digest)

    def scan(self, filename, t=None):
        """Check a QR image at this gate. Gate 1 and Gate 2 checks: TODO 2.6. Gate 3 check: TODO 3.1."""
        t = time.time() if t is None else t
        print(f"   [SCANNER {self.gate}]  scanning {filename}")
        # Read the QR image; its text is ticket + "." + code
        ticket, _, code = ...               # TODO 2.6: read_qr(filename), then .rpartition(".") cuts off the code
        # Gate 1: verify the ticket signature
        details = ...                       # TODO 2.6: check_ticket() of the ticket (TODO 1.2)
        ...                                 # TODO 2.6: if details is None, return "INVALID - signature verification failed"
        ticket_id = details["id"]
        # Gate 2: verify that the code is current
        ...                                 # TODO 2.6: if the code is not current (self.code_is_fresh),
                                            #           return "INVALID - code expired"
        # Gate 3: reject a ticket that has already been admitted; otherwise record it
        ...                                 # TODO 3.1: if ticket_id is in self.seen, return
                                            #           f"REFUSED - already admitted at Gate {self.seen[ticket_id]}"
        ...                                 # TODO 3.1: otherwise record it: self.seen[ticket_id] = self.gate
        print(f"   [SCANNER {self.gate}]  entry list: {self.seen}")
        return "VALID - " + details["name"]

    def sync(self):
        """TODO 3.4  Send this gate's entries to the hub with an HMAC, and merge the entries of other gates."""
        if not self.online:
            print(f"   [SCANNER {self.gate}]  network unavailable - hub not reachable")
            return
        # Step 1: build the message (gate number and local entries) and add its HMAC
        mine = ...                          # TODO 3.4: the ticket ids in self.seen whose gate is self.gate
        message = ...                       # TODO 3.4: a dict with "gate" (self.gate) and "entries" (mine)
        message["mac"] = ...                # TODO 3.4: the HMAC of the message (TODO 3.2)
        print(f"   [SCANNER {self.gate}]  -> HUB: local entries {mine}")
        # Step 2: send the message, then merge the entries of other gates
        reply = ...                         # TODO 3.4: ask() the HUB with the message (no TLS: the HMAC protects it)
        ...                                 # TODO 3.4: for each ticket_id, gate in reply["all"].items():
                                            #           add it to self.seen if it is new (.setdefault)
        print(f"   [SCANNER {self.gate}]  <- HUB: entry list {self.seen}")


# =============================================================================
# TESTS - each test reports PASS or FAIL and names the functions it checks. For a
# failing test, the first incomplete task it depends on is reported, with the line
# numbers of its remaining placeholders (...). A task is identified by the label in
# the comment beside a placeholder, e.g. "# TASK 1.2: ...".
# =============================================================================
results = []
COMPONENTS = [make_ticket, check_ticket, edit_name, totp, save_qr, read_qr, server_tls_context,
              client_tls_context, box_office, Wallet.download, Wallet.show, Scanner.code_is_fresh,
              Scanner.scan, make_mac, hub, Scanner.sync]


LABEL = re.compile(r"#\s*([A-Z]+ \d+\.\d+):")         # task label in a comment, e.g. "# TASK 1.2:"


def task_key(task):
    return [int(n) for n in re.findall(r"\d+", task)]


def incomplete(functions):
    """Incomplete tasks in these functions, in task order: {task: [lines with a placeholder (...)]}."""
    tasks = {}
    for function in functions:
        lines, start = inspect.getsourcelines(function)
        tokens = tokenize.generate_tokens(io.StringIO(textwrap.dedent("".join(lines))).readline)
        rows = sorted({tok.start[0] for tok in tokens if tok.type == tokenize.OP and tok.string == "..."})
        for row in rows:
            text = lines[row - 1].strip()
            label = LABEL.search(text)
            task = label.group(1) if label else function.__qualname__ + "()"
            tasks.setdefault(task, []).append(f"      line {start + row - 1}:  {text}")
    return dict(sorted(tasks.items(), key=lambda item: task_key(item[0])))


def task_labels(functions):
    """All task labels that appear in the comments of these functions."""
    found = {m.group(1) for f in functions for m in LABEL.finditer(inspect.getsource(f))}
    return sorted(found, key=task_key)


def show_help(needs):
    """After a failed test: report the first incomplete task it depends on."""
    earlier = COMPONENTS[:max(COMPONENTS.index(f) for f in needs)]
    for group in (needs, earlier):
        tasks = incomplete(group)
        if tasks:
            task = next(iter(tasks))
            print(f"   ->  {task} is incomplete:")
            print("\n".join(incomplete(COMPONENTS)[task]))
            return
    names = " and ".join(task_labels(needs) or [f.__qualname__ + "()" for f in needs])
    print(f"   ->  {names}: implemented, but the result is incorrect.")
    print("       The [BOX OFFICE] [WALLET] [SCANNER] [HUB] output of this test shows each step.")


@contextmanager
def test(title, *needs):
    """One test. `needs` are the functions it checks."""
    print(f"\nTEST {len(results) + 1}: {title}   [{', '.join(f.__qualname__ for f in needs)}]")
    count = len(results)
    try:
        yield
    except Exception as e:
        print(f"   ERROR: {type(e).__name__}: {e}  ->  FAIL")
        results.append(False)
    if len(results) > count and not results[-1]:
        show_help(needs)


def check(result, expected):
    ok = str(result).startswith(expected)
    results.append(ok)
    print(f"   Result:   {result}\n   Expected: {expected}...  ->  {'PASS' if ok else 'FAIL'}")


def banner(title):
    print("\n" + "=" * 75 + "\n" + title + "\n" + "=" * 75)


def verdict(details):
    return "VALID - " + details["name"] if details else "INVALID - ticket rejected"


# =============================================================================
# TEST SCENARIO
# =============================================================================
def main():
    part = int(sys.argv[1]) if len(sys.argv) > 1 else 3

    banner(f"SUMMER BALL E-TICKET SYSTEM  |  Student ID {STUDENT_ID}  |  Fingerprint {FINGERPRINT}")
    print(f"   Configuration: event {EVENT}; code interval {STEP} s; {DIGITS} digits;")
    print(f"                  box office port {BOX_OFFICE[1]}; hub port {HUB[1]}")

    banner("PART 1 - GATE 1: FORGED TICKETS")
    with test("A valid ticket is accepted", make_ticket, check_ticket):
        valid = make_ticket("T-0100", "Attendee A")
        check(verdict(check_ticket(valid)), "VALID")

    with test("A ticket with a modified holder name is rejected", check_ticket, edit_name):
        check(verdict(check_ticket(edit_name(valid, "Attendee B"))), "INVALID")

    with test("A ticket signed with an unknown key is rejected", make_ticket, check_ticket):
        forged = make_ticket("T-0666", "Unknown Attendee", key=ed25519.Ed25519PrivateKey.generate())
        check(verdict(check_ticket(forged)), "INVALID")

    with test("A validly signed ticket for a different event is rejected", check_ticket):
        other_event = to_bytes({"id": "T-0042", "name": "Attendee C", "event": "su-ball-2026"})
        other_ticket = b64(other_event) + "." + b64(SIGNING_KEY.sign(other_event))
        check(verdict(check_ticket(other_ticket)), "INVALID")

    if part >= 2:
        banner("PART 2 - GATE 2: COPIED QR CODES")
        with test("totp() matches the RFC 6238 test vector", totp):
            code = totp(b"12345678901234567890", 59, step=30, digits=8)
            print(f"   RFC 6238 value for t = 59: 94287082; computed: {code}")
            check(code, "94287082")

        with test("A QR image can be written and read back", save_qr, read_qr):
            save_qr("summer ball test", "test.png")
            check(read_qr("test.png"), "summer ball test")

        make_certificate()
        start_server(BOX_OFFICE, box_office, tls=True)
        wallet_a = Wallet("Attendee A")
        order_code = sell("Attendee A")
        with test("The wallet downloads a ticket over TLS with a valid order code", server_tls_context, client_tls_context, box_office, Wallet.download):
            check(wallet_a.download(order_code), "Ticket downloaded")

        with test("A reused order code is rejected", box_office, Wallet.download):
            check(Wallet("Second device").download(order_code), "REFUSED")

        gate1, gate2, gate3 = Scanner(1), Scanner(2), Scanner(3)
        with test("A QR image generated 5 minutes earlier is rejected", Wallet.show, Scanner.code_is_fresh, Scanner.scan):
            wallet_a.show("old.png", t=time.time() - 300)
            check(gate1.scan("old.png"), "INVALID")

        with test("A current QR image is accepted at Gate 1", Wallet.show, Scanner.code_is_fresh, Scanner.scan):
            wallet_a.show("ticket.png")
            check(gate1.scan("ticket.png"), "VALID")

    if part >= 3:
        banner("PART 3 - GATE 3: REPEATED ENTRY")
        start_server(HUB, hub)
        with test("A second entry with the same ticket at Gate 1 is rejected", Scanner.scan):
            check(gate1.scan("ticket.png"), "REFUSED")

        with test("After Gates 1 and 2 synchronise, the same ticket is rejected at Gate 2", make_mac, hub, Scanner.sync, Scanner.scan):
            gate1.sync()
            gate2.sync()
            check(gate2.scan("ticket.png"), "REFUSED")

        print("\n   Network outage: Gate 1 and Gate 3 are offline")
        gate1.online = gate3.online = False
        wallet_b = Wallet("Attendee B")
        with test("During the outage, a new ticket is accepted at Gate 1", Scanner.scan):
            wallet_b.download(sell("Attendee B"))
            wallet_b.show("ticket_b.png")
            check(gate1.scan("ticket_b.png"), "VALID")

        with test("During the outage, a copy of the same ticket is accepted at Gate 3", Scanner.scan):
            check(gate3.scan("ticket_b.png"), "VALID")

        with test("After the network is restored, the hub raises exactly one DUPLICATE ENTRY alert", hub, Scanner.sync):
            gate1.online = gate3.online = True
            gate1.sync()
            gate2.sync()
            gate3.sync()
            print("   Expected: a single alert, for ticket T-0002")
            check("DUPLICATE ENTRY " + ", ".join(alerts) if alerts else "no alert", "DUPLICATE ENTRY T-0002")

        with test("The hub rejects a message with an invalid HMAC", make_mac, hub):
            reply = ask(HUB, {"gate": 9, "entries": ["T-0099"], "mac": "0" * 64})
            check(reply.get("error", "accepted"), "REJECTED")

    banner(f"SUMMARY: {sum(results)} of {len(results)} tests passed  |  Student ID {STUDENT_ID}  |  Fingerprint {FINGERPRINT}")
    remaining = list(incomplete(COMPONENTS))
    if remaining:
        print(f"Incomplete tasks: {', '.join(remaining)}")
        print(f"Next task: {remaining[0]}")
    if STUDENT_ID.strip() == "00000000":
        print("Warning: STUDENT_ID has the default value 00000000.")


if __name__ == "__main__":
    main()
