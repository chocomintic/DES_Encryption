import copy
from des_constants import *
from des_keygen import get_round_keys
from des_shared import permutate


def encrypt(plaintext: str, key: int) -> str:
    """
    This function will encrypt a plaintext message using the DES algorithm.
    :param plaintext: str, message to be encrypted. ASCII.
    :param key: int, 64-bit. DES key
    :return: str, encrypted message. ASCII.
    """

    # get blocks from plaintext
    blocks = get_blocks(plaintext)

    # get round-keys from key
    round_keys = get_round_keys(key)

    cipher_text_blocks = []
    for block in blocks:
        # we copy the blocks to avoid changing the original blocks / round keys
        tmp_block = copy.copy(block)
        tmp_round_keys = copy.deepcopy(round_keys)

        encrypted_block = encrypt_block(tmp_block, tmp_round_keys)
        cipher_text_blocks.append(encrypted_block)

    ciphertext = get_text_from_blocks(cipher_text_blocks)

    return ciphertext


def decrypt(ciphertext: str, key: int) -> str:
    """
    This function will decrypt a ciphertext message using the DES algorithm
    :param ciphertext: str, message to be decrypted. ASCII
    :param key: int, 64 bit. DES key
    :return: str, resulting plaintext. ASCII.
    """
    #get blocks from ciphertext
    blocks = get_blocks(ciphertext)

    #reverse the round key
    round_key = get_round_keys(key)
    reversed_round_key = round_key[::-1]
    plain_text_block = []

    for block in blocks:
        tmp_block = copy.copy(block)
        tmp_round_keys = copy.deepcopy(reversed_round_key)

        decrypted_block = encrypt_block(tmp_block, tmp_round_keys)
        plain_text_block.append(decrypted_block)

    plaintext = get_text_from_blocks(plain_text_block)

    return plaintext


def encrypt_block(block: list[int], round_keys: list[list[int]]) -> list[int]:
    """
    Performs the DES encrypt operation on the specified block using the passed round keys
    :param block: list[int], 64 bits
    :param round_keys: list[list[int]]. 16 round keys, each 48 bits
    :return: list[int], 64 bits
    """

    # perform the initial permutation
    block = permutate(block, INITIAL_PERMUTATION)

    # split block into left and right half
    def split_list(input_list):
        midpoint = len(input_list) // 2
        return input_list[:midpoint], input_list[midpoint:]    
    left_half, right_half = split_list(block)
    # complete 16 rounds
    for round_num in range(16):
        tmp = right_half
        # expand right half
        right_half = expand(right_half)
        # xor right half with round key
        right_half = xor(right_half, round_keys[round_num])

        # perform substitution on right half
        right_half = substitute(right_half)

        # perform permutation on right half
        right_half = permutate(right_half, PERMUTATION)
        # xor with left half
        right_half = xor(right_half, left_half)
        # the original right half becomes the new left half
        left_half = tmp




    # after all 16 rounds, concatenate the right and left half
    block = right_half + left_half

    # perform final permutation

    block = permutate(block, FINAL_PERMUTATION)

    return block


def get_blocks(text: str) -> list[list[int]]:
    """
    separates text into blocks of 64-bits. Assumes one byte for each character with ASCII encoding
    :param text: str, message
    :return: list[bytearray], list of blocks
    """

    blocks = []
    current_block = []
    for char in text:
        # convert each character into an array of bits
        char_bits = [int(x) for x in bin(ord(char))[2:]]

        # add the bits to the current block with 0-padding to ensure a full byte (8 bits) is added
        current_block += [0] * (8 - len(char_bits))
        current_block += char_bits

        # for Brennon
        if len(current_block) % 8:
            print("Problem in get_blocks function. Size not divisible by 8.")
        elif len(current_block) > 64:
            print("Problem in get_blocks function. Block size too large.")

        # append and start next block once the block size is 64
        if len(current_block) == 64:
            blocks.append(current_block)
            current_block = []

    # perform padding on the last block if necessary
    if 64 > len(current_block) > 0:
        current_block += [0, 1, 1, 1, 1, 1, 1, 1] * ((64 - len(current_block)) // 8)

    # add final block to blocks
    if len(current_block) > 0:
        blocks.append(current_block)

    return blocks


def get_text_from_blocks(blocks: list[list[int]]) -> str:
    """
    converts list of blocks into a string
    :param blocks: list[list[int]], list of 64-bit blocks
    :return: str
    """

    ciphertext = ""
    # for each block
    for block in blocks:
        # 8 bytes in each block
        for byte_num in range(8):
            byte_val = 0
            # 8 bits in each byte
            for bit_num in range(8):
                byte_val += block[byte_num * 8 + bit_num] * (2 ** (7 - bit_num))

            ciphertext += chr(byte_val)

    return ciphertext


def expand(block: list[int]) -> list[int]:
    """
    Expands block using the expansion function for DES
    :param block: list[int], 32 bits
    :return: list[int], 48 bits
    """
    new_list = block + ([0] * 16)
    return permutate(new_list, EXPANSION)


def xor(barray1: list[int], barray2: list[int]) -> list[int]:
    """
    performs bitwise xor between two bit arrays. Must have same size.
    :param barray1: list[int]
    :param barray2: list[int]
    :return: list[int]
    """
    result = [barray1[i] ^ barray2[i] for i in range(len(barray1))]
    return result


def substitute(block: list[int]) -> list[int]:
    """
    performs the DES substitution step
    :param block: list[int], 48 bits
    :return: list[int], 32bits
    """

    result = []

    # get 6-bit chunks of block
    chunks = [block[i * 6: i * 6 + 6] for i in range(8)]

    for idx, chunk in enumerate(chunks):

        # convert to s-box index
        row = chunk[0] * 2 + chunk[5]
        col = chunk[1] * 8 + chunk[2] * 4 + chunk[3] * 2 + chunk[4]
        s_box_idx = row * 16 + col

        val = S_BOXES[idx][s_box_idx]

        val_bin = [int(x) for x in bin(val)[2:]]
        val_bin = [0] * (4 - len(val_bin)) + val_bin

        # for Brennon
        if len(val_bin) != 4:
            print("Error in substitute function. result of s-box lookup is not 4bits.")

        result += val_bin

    return result
