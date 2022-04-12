# Electronic Code Book (ECB) Mode

ECB is a simple and efficient mode of DES. Identical plaintexts with identical keys encrypt to identical ciphertexts.

# PKCS5 Padmode

If the block length is B then add N padding bytes of value N to make the input length up to the next exact multiple of B. If the input length is already an exact multiple of B then add B bytes of value B. Thus padding of length N between one and B bytes is always added in an unambiguous manner. After decrypting, check that the last N bytes of the decrypted data all have value N with 1 < N ≤ B. If so, strip N bytes, otherwise throw a decryption error.

Examples of PKCS5 padding for block length B = 8:

3 bytes: FDFDFD --> FDFDFD0505050505<br/>
7 bytes: FDFDFDFDFDFDFD --> FDFDFDFDFDFDFD01<br/>
8 bytes: FDFDFDFDFDFDFDFD --> FDFDFDFDFDFDFDFD0808080808080808
