local crypt = require "crypt"

-- base64
-- http://en.wikipedia.org/wiki/Base64

local base64_string = "any carnal pleasure."

for i = 20, 15, -1 do
	local s = string.sub(base64_string,1,i)
	print(string.format("Input ends with : %s \tOutput ends with: %s \tInput has %d bytes, output hash %d bytes.",
		s, crypt.base64encode(s), #s, #crypt.base64encode(s)))

	assert(s == crypt.base64decode(crypt.base64encode(s)))
end

-- DH key exchange

local secretA = crypt.randomkey()
local A = crypt.dhexchange(secretA)

print("A private secret = ", crypt.hexencode(secretA), "message->B = ", crypt.hexencode(A))

local secretB = crypt.randomkey()
local B = crypt.dhexchange(secretB)

print("B private secret = ", crypt.hexencode(secretA), "message->A = ", crypt.hexencode(A))

local s1,s2 = crypt.dhsecret(B, secretA), crypt.dhsecret(A, secretB)
assert(s1 == s2)
local secret = s1
print("A B shared secret = ", crypt.hexencode(secret))

assert(crypt.hexdecode(crypt.hexencode(secret)) == secret)

-- DES

local deskey = crypt.hashkey "hello world"
print("hashkey (hello world) = ", crypt.hexencode(deskey))

local hmac = crypt.hmac64(deskey, secret)
print("hmac(hashkey, secret) = ", crypt.hexencode(hmac))

for i=1,30 do
	local etext = crypt.desencode(deskey, string.sub("abcdefghijklmnopqrstuvwxyz1234567890",1,i))
	local dtext = crypt.desdecode(deskey, etext)
	print(crypt.hexencode(etext), "==>", dtext)
end

