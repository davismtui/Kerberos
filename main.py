import getpass
import json
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

REALM_NAME = "@KERBEROS"

AS_TGS_SHARED_KEY = get_random_bytes(32) # YELLOW KEY
TGS_FS_SHARED_KEY = get_random_bytes(32) # PINK KEY

def derive_secret_key(username: str, password: str) -> bytes:
    """
    Derives the given user's secret key from the username and password.
    This one-way derivation function uses SHA256 as the hashing algorithm.
    The salt (combined username and realm name) is prepended to the given
    password so that two different encryption keys are generated for users
    with the same password.
    """
    # THIS METHOD WORKS.

    # create salt
    salt = username + REALM_NAME

    # prepend the salt to the password
    salt_and_pass = salt + password

    # create a hash using the salt
    salt_and_pass_hash = SHA256.new(salt_and_pass.encode()).hexdigest()

    # return the hashed salt and pass in bytes
    return salt_and_pass_hash


def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""

    cipher = AES.new(key, AES.MODE_EAX)

    # get nonce form cipher
    nonce = cipher.nonce

    # serialize the data
    new_data = pickle.dumps(data)

    e_data, tag = cipher.encrypt_and_digest(new_data)

    # return data, tag, and nonce  as one byte stream. (the last 2 are 16 bytes each)
    return e_data + tag + nonce




def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""

    # The following steps are to split the data byte stream into the encrypted data, the tag, and the nonce

    # find length of the entire data
    size = len(data)

    # subtract 32 fom this number: 16 for nonce, 16 for tag.
    size -= 32

    # get the encrypted data of the original object
    real_data = data[0:size]

    # get the tag
    tag = data[(size):(size+16)]

    # get the nonce
    nonce = data[(size+16):]

    # create new cipher, with old ciphers nonce
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    # decrypt the new cipher
    serialized_obj = cipher.decrypt(real_data)

    # de-serialize the decrypted object
    original_obj = pickle.loads(serialized_obj)

    # verify that the message is authentic, with tag.
    try:
        cipher.verify(tag)
        # message is authentic.
    except ValueError:
        print("Key incorrect or message corrupted")
        exit(0)

    # return the original object
    return original_obj


class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""
        try:
            # get relevant password from dictionary  in string format
            pass_wrd = self.users[username] # GREEN KEY
        except KeyError:
            print(f"User does '{username}' not exist in database.")
            exit(0)


        # Message 1: client/TGS session key encrypted using client secret key

        # generate client/tgs session key
        client_tgs_session_key = get_random_bytes(32)

        # Message 2: TGT encrypted using shared key between AS and TGS

        # encrypt derived key with client pass.
        # Lock client_tgs_session_key with password
        msg_1_locked = encrypt(pass_wrd, client_tgs_session_key)

        # create message 2 (TGT)
        TGT = Ticket(username, client_tgs_session_key)

        # encrypt and lock message 2
        # lock with YELLOW KEY
        msg_2_locked = encrypt(AS_TGS_SHARED_KEY, TGT)

        # return tuple
        return msg_1_locked, msg_2_locked


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(
            self,
            tgt_encrypted: bytes,
            authenticator_encrypted: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""

        # decrypt the tgt
        tgt_dec = decrypt(AS_TGS_SHARED_KEY, tgt_encrypted)

        auth_dec = decrypt(tgt_dec.session_key, authenticator_encrypted)

        # if the authenticator is valid, send the messages
        if auth_dec.username == tgt_dec.username:

            # generate client/FS session key
            client_FS_session_key = get_random_bytes(32) # BLUE KEY

            #  Message 5: client/FS session key encrypted using client/TGS session key

            # this is ok (F)
            msg_5 = encrypt(tgt_dec.session_key, client_FS_session_key)

            # Message 6: service ticket encrypted using shared key between TGS and FS

            # create service ticket "token"
            service_ticket = Ticket(username=tgt_dec.username, session_key=client_FS_session_key)

            # this is OK
            msg_6 = encrypt(TGS_FS_SHARED_KEY, service_ticket)

        else:
            print("Authenticator is not valid, usernames do not match.")
            exit(0)

        return msg_5, msg_6 # client_fs_key, service ticket token


class FileServer:
    """The file server in Kerberos."""

    def request_file(
            self,
            filename: str,
            ticket_encrypted: bytes,
            authenticator_encrypted: bytes,
    ) -> Optional[bytes]:
        """Requests the given file from the file server by using the given service ticket and authenticator as authorization."""

        # Message 9: the file request response encrypted using the client/FS session key
        token = decrypt(TGS_FS_SHARED_KEY, ticket_encrypted)

        dec_auth = decrypt(token.session_key, authenticator_encrypted)

        # check to see if usernames match
        if dec_auth.username == token.username:

            # open file and read data into string variable
            with open(filename, "r") as f:
                data = f.read()

            # create file response object
            response = FileResponse(data, dec_auth.timestamp)

            enc_response = encrypt(token.session_key, response)

            # return response to client
            return enc_response

        # if usernames dont match, exit.
        else:
            print("Authenticator is not valid, usernames do not match.")
            exit(0)


class Client:
    """The client in Kerberos."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.secret_key = derive_secret_key(username, password)

    @classmethod
    def from_terminal(cls):
        """Creates a client object using user input from the terminal."""

        username = input("Username: ")
        password = getpass.getpass("Password: ")
        return cls(username, password)

    def get_file(self, filename: str):
        """Gets the given file from the file server."""

        # Message 3: client forwards message 2 (TGT) from AS to TGS

        # create a Authentication server object
        AS = AuthenticationServer()

        # get TGT and client/TGS session key from AS (in that order)
        response_msg_1, response_msg_2 = AS.request_authentication(username=self.username)


        # Message 4: authenticator encrypted using client/TGS session key

        # create authenticator
        authenticator = Authenticator(self.username)

        # try to decrypt the client/TGS session key with the given password
        try:

            # decrypt response message 1 using client password to get the client/TGS session key
            client_TGS_session_key = decrypt(bytes.fromhex(self.secret_key), response_msg_1)

        # if we are unable to decrypt the client/TGS session key with the password, we know the password is wrong
        # print error message, and exit program
        except pickle.UnpicklingError:
            print("Failed to decrypt client/TGS session key.")
            exit(0)

        # encrypted authenticator
        msg_4 = encrypt(client_TGS_session_key, authenticator)

        # create a Ticket Granting Server object
        TGS = TicketGrantingServer()

        # forward the authentication server message (encrypted TGT) and authenticator to the ticket granting server,
        # get response messages
        response_msg_5, response_msg_6 = TGS.request_authorization(response_msg_2, msg_4)

        # Message 7: client forwards message 6 (service ticket) from TGS to FS

        # create file server object
        FS = FileServer()

        # create new authenticator ticket
        new_authenticator = Authenticator(self.username)

        # get Client/Server Session Key from response message 5
        client_FS_session_key = decrypt(client_TGS_session_key, response_msg_5)

        # Message 8: authenticator encrypted using client/FS session key

        # Encrypt the authenticator with the Client/File Server Session Key.
        enc_auth = encrypt(client_FS_session_key, new_authenticator)

        # request file, and get File Server response (response_msg_6 is the service ticket token)
        enc_response = FS.request_file(filename, response_msg_6, enc_auth)

        # decrypt FS response using client/FS key
        FS_response = decrypt(client_FS_session_key, enc_response)

        # verify the FS's true identity and willingness to serve the client
        if FS_response.timestamp == new_authenticator.timestamp:
            # if the FS is authentic, and willing to give file. print it
            print("Retrieved " + filename + " from FS:\n" + FS_response.data)
        else:
            # if the timestamps dont match, fs cant be trusted, exit
            print("File Server cannot be trusted")
            exit(0)


@dataclass(frozen=True)
class Ticket:
    """A ticket that acts as both a ticket-granting ticket (TGT) and a service ticket."""

    username: str
    session_key: bytes
    validity: float = field(init=False, default_factory=lambda: time.time() + 3600)


@dataclass(frozen=True)
class Authenticator:
    """An authenticator used by the client to confirm their identity with the various servers."""

    username: str
    timestamp: float = field(init=False, default_factory=time.time)


@dataclass(frozen=True)
class FileResponse:
    """A response to a file request that contains the file's data and a timestamp to confirm the file server's identity."""

    data: str
    timestamp: float


if __name__ == "__main__":
    client = Client.from_terminal()
    client.get_file("test.txt")
