import pickle
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import os

class PasswordManager:
  MAX_PASSWORD_LEN = 64;

  def __init__(self, password, data = None, checksum = None):
    self.salt = -1
    self.kvs = {}
    self.key = b'-1'
    if data is not None:
      try:
        self.kvs = pickle.loads(bytes.fromhex(data))
        self.salt = self.kvs['salt']
        self.kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32, salt = self.salt, iterations = 2000000)
        self.key = self.kdf.derive(bytes(password,'ascii'))
      except:
        print('given data is malformed')
        raise ValueError
      #anyway
      validator = self.hashDomain(data)
      if validator.hex() != checksum:
        raise ValueError
    else:
        self.salt = os.urandom(16)
        self.kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32, salt = self.salt, iterations = 2000000)
        self.key = self.kdf.derive(bytes(password,'ascii'))
        self.kvs['salt'] = self.salt
        self.kvs['var'] = 1

  #returns a hex encoded representation of the password manager along with a hex encoded checksum
  def dump(self):
    #TODO: add checksum, document says it is a SHA-256 encoded version of the manager??? maybe of the serialization>>
    output = pickle.dumps(self.kvs).hex()
    checksum = self.hashDomain(output)
    return output, checksum.hex()

  #gets the password associated with the given domain name
  def get(self, domain):
    hashD = self.hashDomain(domain)
    if hashD in self.kvs:
        
        encryptedPass = self.kvs[hashD]
        
        decryptedPass = self.decryptPassword(encryptedPass[0],encryptedPass[1],hashD)
        return decryptedPass.decode()
    return None
    #HELPER FUNCTION ZONE!!

    #note: probably, take the salt, add the variance, then hash it. 
    #note: what length is the nonce suppsoed to be? A: same length as block_size of encryption AES is 16byte, so sha 128 i guess
  def generateNonce(self):
      mac = HMAC(self.key,hashes.SHA256())
      saltVal = int.from_bytes(self.salt,'little')
      seed = saltVal + self.kvs['var']
      seed = seed.to_bytes(16,'little')
      self.kvs['var'] = self.kvs['var'] + 1
      mac.update(bytes(str(seed),'ascii'))
      nonce = mac.finalize()
      nonceGenerator = Cipher(algorithms.AES(self.key), modes.CTR(self.salt))
      enc = nonceGenerator.encryptor()
      product = enc.update(nonce[:16]) + enc.finalize()
      return product[:16]

  #not needed, AAD used to prevent swap attack instead.
 #def buildAAD(self,password):
      #mac = HMAC(self.key,hashes.SHA256())
      #mac.update(password)
      #aad = mac.finalize()
      #return aad

  #creates a sha256 hashed encryption of a domain name
  def hashDomain(self, domain):
      mac = HMAC(self.key,hashes.SHA256())
      mac.update(bytes(domain,'ascii'))
      hashD = mac.finalize()
      return hashD

  def addPadding(self, toPad,size):
      padder = padding.PKCS7(size).padder()
      padded_data = padder.update(toPad)
      padded_data += padder.finalize()
      return padded_data

  def removePadding(self,toUnpad,size):
      unpadder = padding.PKCS7(size).unpadder()
      data = unpadder.update(toUnpad)
      return data + unpadder.finalize()

  def encryptPassword(self, password, hashD):
      #NOTE: had to chagne from MAX_PASSWORD_LENGTH * 8 to just 512? could be indentaiton problem
      paddedPassword = self.addPadding(password,512)
      aesgcm = AESGCM(self.key)
      nonce = self.generateNonce()
      #TODO: is this insecure? i dnt think so because it never goes out
      #tempEncrypt = aesgcm.encrypt(nonce,paddedPassword,None)
      encPassword = aesgcm.encrypt(nonce,paddedPassword,hashD)
      return [encPassword, nonce]
   

  def decryptPassword(self, encPassword, nonce, domain):
      aesgcm = AESGCM(self.key)
      paddedPassword = aesgcm.decrypt(nonce,encPassword,domain)
      unpaddedPassword = self.removePadding(paddedPassword,512)
      return unpaddedPassword

  #for use with chr(x) to always produce alphanumeric when given num 0-61
  def asciiConverter(self,num):
    modNum = 48 + num
    if num >= 10:
        modNum = modNum + 7
    if num >= 36:
        modNum = modNum + 6
    return modNum

  def charGenerator(self,domain):
    paddedDomain = self.addPadding(domain,128)
    charGenerator = Cipher(algorithms.AES(self.key), modes.CTR(self.salt))
    enc = charGenerator.encryptor()
    product = enc.update(paddedDomain) + enc.finalize()
    val = int.from_bytes(product,'little')
    #62 = total number of alphanumeric characters
    num = val % 62
    asciiVal = self.asciiConverter(num)
    return chr(asciiVal)


  #adds a domain:password pair to the manager
  def set(self, domain, password):
    if len(password) > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')
    
    #TODO: whole thing
    #STEPS: 
    #1, take the domain, and hash it using HMAC <- made hashDomain
    #2, take the password and pad it <- made addPadding
    #3, take the padded password and encrypt using AES <- made encryptPassword
    #4, add to password bank :)
    hashD = self.hashDomain(domain)
    enrcyptedPassword = self.encryptPassword(bytes(password,'ascii'),hashD)
    self.kvs[hashD] = enrcyptedPassword
    #COMPLETE :)

  #removes the password for the given domain from the manager
  def remove(self, domain):
    hashD = self.hashDomain(domain)
    if hashD in self.kvs:
                #TODO: since domains have to be hash enocded, call HMAC on domain with the key in order to
      del self.kvs[hashD]
      return True

    return False

  #generates a new pseudorandom password of the desired length for a given domain
  def generate_new(self, domain, desired_len):
    if domain in self.kvs:
      raise ValueError('Domain already in database')
    if desired_len > self.MAX_PASSWORD_LEN:
      raise ValueError('Maximum password length exceeded')

    #TODO randomize this, with aes and hashes i guess?
    nuDomain = domain
    if(len(domain) > 8):
        nuDomain = domain[:8]
    new_password = ''
    for i in range(0,desired_len):
        varDomain = nuDomain + str(self.kvs['var'])
        self.kvs['var'] = self.kvs['var'] + 1
        varDomain = bytes(varDomain,'ascii')
        new_password = new_password + self.charGenerator(varDomain)
    #new_password = '0'*desired_len
    self.set(domain, new_password)
    return new_password