# Imports
import base64, time, datetime, random, os, socket, pickle, sys
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import oid
from cryptography.x509.oid import NameOID
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

# These variables are to support the mock camera
my_pict = "iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAMAAAC5zwKfAAADAFBMVEWOjo6JiYmxsbGFhYWfn5+oqKiXl5eRkZGBgYGMjIx9fX0JCQl4eHgWFha6urpwcHBkZGQiIiLBwcFSUlJBQUEwMDDGxsbMzMzU1NTk5OQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAazXNTAAAACXBIWXMAAAsTAAALEwEAmpwYAAALaElEQVRYhW2Y65LcOI6FP1wkSmXZ7d3pef/n28t0uNtZJVEkgf0hZbp6YhWRlRVS8giXgwOQsh6wHGsFpkRDibrGVOSRpEhxtHuHDg6dkvypX8eHncSyvxEazSvrXmpROBwWAEIBjvlgJjCoZnPRHhzzAeDgHd/R7wcIz4UwJQAF2FcHjgVQJqhy/wbp8zodJ07XHqAO/VR3731Hx0g+X+vrP+VCgwm9brBSSfvWPgA6oKj38wyiH0dH+ZAvjOm4V76uTzd0oilABQ7mIceH3s8iIHowv80zEUTA2X/bkoN4AuyFykLZ9RmL6WV51ZRlV43AvROqAQEdx2fl7W1W1Y9cplyJX0YW2CnOE226bWZlrDtXHvplf+gF2Z9BAI3+FmEaxNMQVqj6hKERAMHga0MjmOlBKO6z4zNHv9zFPSKU9tu1BPZfcVQ4nlY3gCXPtwMCZgdldnfH/cTdXYl4Lpw5NgJo3B7t1NvlVxAX9vJ1f73JPRNCLBwnpaPB7DBfroe//yIMUKjOi6AKyu7rE6/j3pJhkgwnBdy5vnsngHPd6/QLTQP8iQVQ5Zj1yW33GGdjpiYaTUmuRyZyQKAB+3/8q67xjOFOuQCPL3dgmM/fP+73ZTtHYnV3dOSwnjCdJr1MXqSfBMzs//nzxZsKYBPdu5Ogfen6tYKmLtZr242IVJBcz8zMTAvIfM8hpaMy65DcRcdV6qN8TgrALFODoPS+xzwTCJLSebDBgxBJIuW0GOseejjeNF4G1lf0LgrufPlA0bmf+zwnITLGiAEXHpByRbLysRJxxuHzwkq51KbcgqAXCUtXFMV6xA4hjA02tu27w7ZtjBgBkN453gBCctS9XGkuzyxfNFyidCDm3tsSGcKADTbHuwN9gwfDhNCzRNNQwmHda3nivOSnwZHTqQROi0jIwQbujuP3xQYDhLnRCyzzsTwL8Am4PCtxwSHQzFiQkLjR3EWESxWeiJEzvb/RHW9PyrwsnOKqPJPrZWOJTIFt6/hnHviNCBLRNNPP7uO3LPx/LkecgoJjgQTwuAVMIKG741f5DSAjRvpbP0EoUGv9GyCQ9FuCFWBsAPROZgL0ox/03rftCiNG4vR+95fyBCy3crGel+zLQQIPHv2+rgh6p998HLBcls/hAVDKy+X67E6OQ1xBk3G99nGbf2PCY3v6AyLiri9tuWGeSQ4MHO10BeyC23Dc6c9+8ACuvOxXFHrYjVcK4Pt6N9WrJPsV7iTFBmw4cLEacPr2srm0BccPRH6FEL3QLpUcdBSH+SmKjwupf/pcl0EtV8rm9vS4Xi6XQ6Mx0W7bO/mMERsXua8vd3fYNoxrGJEjcB55efxKCjDRflGoR1dRecYKmD7V3lXOCWVPAtwL9fK41EscFGgQJgBh+6nH0uRShct5mUASSBwwRCoyUqOb6BW+Sing7GWiTRMs9wCUFAhtkx6SEWwrcvWm7D8m6cNDRYYFncDJpzaU+lm+bo3V0IFSWderFhgfj20Fkv8x+eaQI9vke1v3+gWQyDvLd0/pbiI0k6B0RZyAty+AmIqIBMfHG3B0m2chUZ1S5zmtr5Hp/OX1ThvgOxBtgoCqofhJfDntp4UMEzvXaUCf8nhondoYTcDn7s6uw7uD5EtrQNdfUmZ3AKpL+UN7pIsc83lgdNShnPvZRDTrz/09bQo6ML5dQawVqP6aPluUfQGHyY7dMr67dH+v6zuLPBa6iQ6T2YXsHyH7xMJyeNf9k2QVm6Z9YlhYpImGqJ5xJCzfjjrKR/3nu5o1k76L9pTvR5v6w7/0Eb2fi6F6jLsPMrwOhVWhodMc0Rbv0AZMnh997fMcSTLJ48FoMcH5huVf/YtlzJJJj2NcQSvrleV90tSYJEkky+nnmFF5DNfzrNGzizQVTbCII99b73PXAQz3ZFSbEyqjl0pROAggGpDvQB0js09Ea9ubtK7eiAFz0SE5vn+fNPO9B0mA/XUJ2Z3o6pQTrRenbRgvZQiMn2PjIxuowL7YGPADywwZlqKaZIqscfO6VPRAiQlYyPOeT5UxkIDBY1e/h9a1VgPMkIxhA5lQ+2l2VWwF6oou9VIbOJiFP+Zx8WhgpJoSmjOAHOqnmkEmZpjglsfin7ZA6/6UrAZ70Vz/Kc5EADZAhMCGn1NAMuVkOcYQGZCZGUJfy8Xpyrqygx63Wjea8RC7ZMIMYAw0W9cvjXWVCaWJmY2VceuJlLZq2z8N2ia4BkYkYfKQRcahSEpmYuPL6ulCTlTakuMfUpMTVFQQ1/bBKdkLgz4d69T9NdmwnF2cZBKNlMEGLNJ+fqukPID5/ctx+O+98wDimsbzMZ3XnL9S2NFnzwMIs2vbekXWl5X9ry+H7DG275vk9LCPfrD49op8iAn7Wl+J1uc2CoilHmW8drju0v53p4+Rsr2VBWFy9ccPYBsgTJbHiKbsT8laX40pgFnEPEVOuRpU33/qQGcxJ4O0phIdO+52Xx3YvDzrZIfPLQCgnD++kdNRAPpDdVgOE+bjgXnVqevO2Mf2DNLQx9XaSuXaoL2kLKBW1Mjb8MdDtZOWQ0Zdcpqql56SRvoDAy2dLpptusWVlU99GWBGRyKclTRUE1O1E8uj9DpJbT1VHXEDTm30VXTlUwf4+xYfVQbZ5lkYpiGuAhxDc4hJDBhnN/KiPaCPVLtnwStozr78AozihRFBCpmC9HmXLIwQAp1FD5lDZfewgGmsMzlg3Z+NpPpy6RXqcKzDwKiOgGTqHDMx7jFfyGE6IF22XefhptLvjv4sv5uHQL32uQNKQfkeiRmJmKK2fd8sU8Y86zzgqxM0yP7Smv3vtFE41qvrCWDdt50hS0o2DeXdewnHJzwlxY9EdJLMWyc+J6XdrLnIlGl6gh6+ImF8vLu2Yzb+0Wb92H423t9Y5YGOWRiMX9ueFXac41ei6xo6HE2G7F8hx77ybZY3pKT8Dm//vcx/ysNoJqlXsoPleZSxsr569AvVhviimfIDsLN/Pf/1fj3J+K8/vs4/3Gz4jwzENX+p/2u9IJYgI8V7TzNRyUg5vSoip/g8/vhYhfyjlcJfjgwOAz2/SoccQp86MPU+XeM40G6yB8NTPDLmUEiRs2u18WcgHkeppjkMkJRN8hpCgXVfeZXepNdub2FlCXKIT0KopSoZ0UWngOwj0wwsyUw9iyT577WGc52iKeuxwG4OITJlCIokRgR8h/4wzymSoWmJfHspn9zKtX7m4d164wxsuNNjqAU6UlLDfg7MUu0UwbKPKdLvEnuyZv8k/deNBXaWgOy4d5U8OTWHmqurt6YMkUx0TcZX4qXtK+uzUFYTZA7QkcOZjp6GSqjlOeFdNEkBRNwSBFTtnCnzUEbCuM6HOjBxOP7JaPZ1jRMgu39hLxMRGhJC6LjPlQiT8mFvJH87NV352wnn8+blM3J0XRY6omiqpPQISEgFDdmscxl4I7xaver14XmmtrcYTvvZvPTmFRE7kcG2kUiqaLdWfLQnwucTDI7DNGfNRMYC0N1Dig3rx6ouoil11kTzPFNpkyAlZdEa12FI5vOMjaMDi35Gh5XqOtpfNi07rqbUNZ7lkOoJ3Vis1l9b9Ofy6++/8ZzKeIufE/BRKWNq8xhDr/MHAVI33OqYyr+ytGubfnD8SshnwAX24vOBJW2f3yvONwklsQcwUgMTYd9pMv2Iyi2vCy/h11dcD2CfB29ofB0Upr0isvQgU8xUjbDZoaeNILNv1+Z+OY7jhfXJwiXarNv3Hde5FQjvRyK/uUFkQsqYLPPcB2jy3XWte1wn4ctyo/kLch66eW1NHaQZMMyO8xtuNZXI03w2aGmhErxNY2frf+ZyLMcCEBpgimmAmH/J0XPORc9Y3moimYp2pCGoqk0a5McgSLXU+fTR47fpyL4AHRL0/wCh2bfAENQtdQAAAABJRU5ErkJggg=="



# Socket Programming
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 8000
soc.connect((host, port))

# System variable of main program
camera_id = 100


def get_picture():
    """This function simulate a motion activated camera unit.  It will return 0 byte if no motion is detected.
    Returns:
        bytes: a byte array of a photo or 0 byte no motion detected
    """    
    time.sleep(1) # simulate slow processor
    if random.randrange(1,10) > 8:  # simulate no motion detected
        return b''
    else:
        return my_pict

global decode
def decode(string):
    string2 = ""
    for byte in string:
        string2 += str(byte)
        print(format(byte, '02x'), end="")
    print("")
    return string2

# Extracts server certificate and server public key
cert = open("./depolyment/server_certificate.der", "rb").read()
server_certificate = x509.load_der_x509_certificate(cert, default_backend())
server_public_key = server_certificate.public_key() 

server_rsakey_pair = RSA.generate(2048)
server_public_key2 = server_rsakey_pair.public_key()
server_private_key = server_rsakey_pair

camera_rsakey_pair = RSA.generate(2048)
camera_public_key = camera_rsakey_pair.public_key()
camera_private_key = camera_rsakey_pair

with open('./depolyment/server_public.pem', 'wb') as f:
    f.write(server_public_key2.export_key('PEM'))

with open('./depolyment/server_private.pem', 'wb') as f:
    f.write(server_private_key.export_key('PEM'))

with open('./depolyment/camera_public.pem', 'wb') as f:
    f.write(camera_public_key.export_key('PEM'))

with open('./depolyment/camera_private.pem', 'wb') as f:
    f.write(camera_private_key.export_key('PEM'))

print(f"Server Public Key: {server_public_key}")
# Outputs Certificate Details
def certificate_details():
    def get_pubkey_id(pubkey_object):
        if isinstance(pubkey_object, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(pubkey_object, ec.EllipticCurvePublicKey):
            return "ECC"
        elif isinstance(pubkey_object, dsa.DSAPublicKey):
            return "DSA"
        else:
            return None

    def getNameStr(subj):
        ans = []
        l = [('CN', NameOID.COMMON_NAME)]
        l.append(('OU', NameOID.ORGANIZATIONAL_UNIT_NAME))
        l.append(('O', NameOID.ORGANIZATION_NAME))
        l.append(('L', NameOID.LOCALITY_NAME))
        l.append(('ST', NameOID.STATE_OR_PROVINCE_NAME))
        l.append(('C', NameOID.COUNTRY_NAME))
        for e in l:
            att = subj.get_attributes_for_oid(e[1])
            if att:
                ans.append("{0}={1}".format(e[0], att[0].value))
        return ",".join(ans)

    print("Version: {0}".format(str(server_certificate.version)))
    print("Serial No: {0:x}".format(server_certificate.serial_number))
    subjStr = getNameStr(server_certificate.subject)
    print("Subject: {0}".format(subjStr))
    signature_algo_oid = server_certificate.signature_algorithm_oid
    # updated due to change in Cyrptography API change
    print("Signature Algorithm: {0}".format(signature_algo_oid._name))
    print("Key {0} public key, {1} bits".format(
        get_pubkey_id(server_public_key), server_public_key.key_size))
    
    print("Public Numbers:", end=" ")
    nstr = str(server_public_key.public_numbers().n)
    while len(nstr) > 0:
        print(nstr[:80])
        nstr = nstr[80:]

    print('Public exponent: {0}'.format(server_public_key.public_numbers().e))
    # insert your codes to display the validity info of the cert
    print("Validity:")
    print("From: {0}".format(
        server_certificate.not_valid_before.strftime("%a %b %d %H:%M:%S %Y")))
    print("To: {0}".format(server_certificate.not_valid_after.strftime("%a %b %d %H:%M:%S %Y")))
    issuerStr = getNameStr(server_certificate.issuer)
    print("Issuer: {0}".format(issuerStr))
    return

print(f"[CERTIFICATE DETAILS]")
certificate_details()
input("")
os.system("cls")

# Encrypts the image with AES 256 Bits using the session AES key
def encryption(arg, aes_key, iv):
    block_size = 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv) # AES Cipher in CBC Mode
    bytes = pad(arg.encode(), 16)
    encrypted = cipher.encrypt(bytes)
    return encrypted
    
# Encrypts AES Key using server public key with RSA
def encrypt_aes_key(aes_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key

def connect_server_send( file_name: str , file_data: bytes , dictionary) -> bool:
    try:
        if random.randrange(1,10) > 8:
            print("Generated Random Network Error")   # create random failed transfer
            return False
            
        else:
            key_list = list(dictionary.keys())
            for k in key_list:
                dict_to_send = {k: dictionary[k]}
                soc.sendall(pickle.dumps(dict_to_send))
                time.sleep(1)
            return True

    except Exception as e:
        print(e, "while sending", file_name )
        return False

while True: # Main function
    try: 
        my_image = get_picture()  # get picture
        if len(my_image) == 0:
            time.sleep(10) # sleep for 10 sec if there is no image
            print("Random no motion detected")

        else:
            os.system("cls")
            # Generate new session AES key
            print("GENERATING A NEW AES SESSION KEY...")
            # Generate random bytes (128 bits)
            session_aes_key = get_random_bytes(AES.block_size)
            iv = get_random_bytes(AES.block_size)
            # Output AES Session Key and IV
            print(f"[AES SESSION KEY]")
            # Outputs AES Session Key bytes
            print(f"Key: {session_aes_key.hex()}")
            # Outputs IV bytes
            print(f"Initialization Factor: {iv.hex()}")
            encrypted_image = encryption(my_image, session_aes_key, iv)  # Get encrypted image
            encrypted_aes_key = encrypt_aes_key(session_aes_key, server_public_key2)
            send_to_server = {}
            f_name = str(camera_id) + "_" +  datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S.jpg" )
            encrypted_filename = encryption(f_name, session_aes_key, iv)
            encrypted_camera_id = encryption(str(camera_id), session_aes_key, iv)
            send_to_server["Filename"] = encrypted_filename
            send_to_server["EncryptedCameraID"] = encrypted_camera_id
            send_to_server["EncryptedImage"] = encrypted_image
            send_to_server["EncryptedAESKey"] = encrypted_aes_key
            send_to_server["IV"] = iv

            print("Sending image....")
            if connect_server_send(f_name , encrypted_image, send_to_server): 
                print(f_name , " sent" )
                time.sleep(1)
                reply = soc.recv(5120)
                print(reply.decode())
            else:
                
                print("Sending image unsuccessful")
            

    except KeyboardInterrupt:
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "127.0.0.1"
        port = 8000
        soc.connect((host, port))
        soc.sendall(pickle.dumps(["QUIT"]))
        soc.close()
        sys.exit()  # gracefully exit if control-C detected
