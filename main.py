import ntlm_auth

# Encrypt the sensitive information
encrypted = ntlm_auth.ntlm_encrypt(b'Manulis13615@')
print(encrypted)
# Decrypt the sensitive information
decrypted = ntlm_auth.ntlm_decrypt(encrypted)
print(decrypted)
